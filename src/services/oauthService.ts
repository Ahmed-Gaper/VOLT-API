import axios from 'axios';
import { config } from '../config/config.js';
import { User } from '../models/user.js';

export interface SocialUserData {
  id: string;
  email: string;
  name: string;
  picture?: string;
  provider: 'google' | 'facebook';
}

export class OAuthService {
  static async verifyGoogleToken(accessToken: string): Promise<SocialUserData | null> {
    try {
      const response = await axios.get(
        `https://www.googleapis.com/oauth2/v2/userinfo?access_token=${accessToken}`
      );

      const data: unknown = response.data;
      const raw = data as Record<string, unknown>;
      const id = String(raw.id ?? '');
      const email = String(raw.email ?? '');
      const nameStr =
        typeof raw.name === 'string' && (raw.name as string).length > 0 ? (raw.name as string) : '';
      const picture = typeof raw.picture === 'string' ? (raw.picture as string) : undefined;

      if (!id || !email) {
        throw new Error('Invalid Google token response');
      }

      const [emailFirstPart = ''] = email.split('@');
      const safeName: string = nameStr || emailFirstPart;
      const result: SocialUserData = {
        id,
        email,
        name: safeName,
        provider: 'google',
      };
      if (typeof picture === 'string' && picture.length > 0) {
        result.picture = picture;
      }
      return result;
    } catch (error) {
      console.error('Google token verification failed:', error);
      return null;
    }
  }

  /**
   * Verify Facebook OAuth token and get user data
   */
  static async verifyFacebookToken(accessToken: string): Promise<SocialUserData | null> {
    try {
      const fields = ['id', 'name', 'email', 'picture.type(large)'].join(',');
      const response = await axios.get(
        `https://graph.facebook.com/v19.0/me?fields=${encodeURIComponent(fields)}&access_token=${accessToken}`
      );

      const data: unknown = response.data;
      const raw = data as Record<string, unknown>;
      const id = String(raw.id ?? '');
      const email = String(raw.email ?? '');
      const nameStr =
        typeof raw.name === 'string' && (raw.name as string).length > 0 ? (raw.name as string) : '';
      // picture may be nested: { picture: { data: { url } } }
      let picture: string | undefined;
      const pictureObj = (raw.picture as Record<string, unknown>)?.['data'] as
        | Record<string, unknown>
        | undefined;
      if (pictureObj && typeof pictureObj.url === 'string') {
        picture = pictureObj.url as string;
      }

      if (!id || !email) {
        // Email may be missing if the user denied email scope or it's not available
        throw new Error('Invalid Facebook token response: missing id or email');
      }

      const [emailFirstPart = ''] = email.split('@');
      const safeName: string = nameStr || emailFirstPart;
      const result: SocialUserData = {
        id,
        email,
        name: safeName,
        provider: 'facebook',
      };
      if (typeof picture === 'string' && picture.length > 0) {
        result.picture = picture;
      }
      return result;
    } catch (error) {
      console.error('Facebook token verification failed:', error);
      return null;
    }
  }

  static async findOrCreateSocialUser(
    socialData: SocialUserData
  ): Promise<{ user: import('../models/user.js').IUser; isNewUser: boolean }> {
    try {
      // First, try to find user by social ID
      let user = await User.findOne({
        socialId: socialData.id,
        authProvider: socialData.provider,
      });

      if (user) {
        return { user, isNewUser: false };
      }

      // If not found by social ID, try to find by email
      user = await User.findOne({ email: socialData.email });

      if (user) {
        // Link the social account to existing user
        user.authProvider = socialData.provider;
        user.socialId = socialData.id;
        if (socialData.picture && !user.profilePicture) {
          user.profilePicture = socialData.picture;
        }
        await user.save();
        return { user, isNewUser: false };
      }

      // Create new user
      const [emailLocalPart = ''] = (socialData.email || '').split('@');
      const username = await OAuthService.generateUniqueUsername(emailLocalPart);

      user = new User({
        username,
        email: socialData.email,
        displayName: socialData.name,
        authProvider: socialData.provider,
        socialId: socialData.id,
        ...(socialData.picture && { profilePicture: socialData.picture }),
        isVerified: true, // Social accounts are considered verified
      });

      await user.save();
      return { user, isNewUser: true };
    } catch (error) {
      console.error('Error finding or creating social user:', error);
      throw error;
    }
  }

  private static async generateUniqueUsername(baseUsername: string): Promise<string> {
    const username = baseUsername.toLowerCase().replace(/[^a-z0-9]/g, '');
    let counter = 1;
    let finalUsername = username;

    while (await User.findOne({ username: finalUsername })) {
      finalUsername = `${username}${counter}`;
      counter++;
    }

    return finalUsername;
  }

  /**
   * Get OAuth URLs for frontend redirection
   */
  static getOAuthUrls() {
    const baseUrl =
      config.NODE_ENV === 'production' ? 'https://yourdomain.com' : 'http://localhost:8000';

    return {
      google: `https://accounts.google.com/o/oauth2/v2/auth?client_id=${config.GOOGLE_CLIENT_ID}&redirect_uri=${baseUrl}/api/auth/google/callback&response_type=code&scope=openid%20email%20profile`,
      facebook: `https://www.facebook.com/v19.0/dialog/oauth?client_id=${config.FACEBOOK_APP_ID}&redirect_uri=${baseUrl}/api/auth/facebook/callback&response_type=code&scope=email,public_profile`,
    };
  }
}
