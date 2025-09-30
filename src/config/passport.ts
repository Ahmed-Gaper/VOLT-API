import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as FacebookStrategy } from 'passport-facebook';
import { config } from './config.js';
import { OAuthService } from '../services/oauthService.js';

// Google OAuth Strategy
passport.use(
  new (GoogleStrategy as unknown as new (
    options: { clientID: string; clientSecret: string; callbackURL: string },
    verify: (
      accessToken: string,
      refreshToken: string,
      profile: passport.Profile,
      done: (err: Error | null, user?: Express.User | false | null, info?: unknown) => void
    ) => void | Promise<void>
  ) => passport.Strategy)(
    {
      clientID: config.GOOGLE_CLIENT_ID,
      clientSecret: config.GOOGLE_CLIENT_SECRET,
      callbackURL: '/api/auth/google/callback',
    },
    async (
      accessToken: string,
      refreshToken: string,
      profile: passport.Profile,
      done: (err: Error | null, user?: Express.User | false | null, info?: unknown) => void
    ) => {
      try {
        const socialData = {
          id: profile.id,
          email: (profile.emails && profile.emails[0] && profile.emails[0].value) || '',
          name: profile.displayName || profile.name?.givenName || '',
          ...(profile.photos?.[0]?.value && { picture: profile.photos[0].value }),
          provider: 'google' as const,
        };

        const { user, isNewUser } = await OAuthService.findOrCreateSocialUser(socialData);
        return done(null, { user, isNewUser } as unknown as Express.User);
      } catch (error) {
        return done(error as Error, null);
      }
    }
  )
);

// Facebook OAuth Strategy
passport.use(
  new (FacebookStrategy as unknown as new (
    options: {
      clientID: string;
      clientSecret: string;
      callbackURL: string;
      profileFields?: string[];
    },
    verify: (
      accessToken: string,
      refreshToken: string,
      profile: passport.Profile,
      done: (err: Error | null, user?: Express.User | false | null, info?: unknown) => void
    ) => void | Promise<void>
  ) => passport.Strategy)(
    {
      clientID: config.FACEBOOK_APP_ID,
      clientSecret: config.FACEBOOK_APP_SECRET,
      callbackURL: '/api/auth/facebook/callback',
      profileFields: ['id', 'displayName', 'emails', 'photos'],
    },
    async (
      accessToken: string,
      refreshToken: string,
      profile: passport.Profile,
      done: (err: Error | null, user?: Express.User | false | null, info?: unknown) => void
    ) => {
      try {
        const socialData = {
          id: profile.id,
          email: (profile.emails && profile.emails[0] && profile.emails[0].value) || '',
          name: profile.displayName || profile.name?.givenName || '',
          ...(profile.photos?.[0]?.value && { picture: profile.photos[0].value }),
          provider: 'facebook' as const,
        };

        const { user, isNewUser } = await OAuthService.findOrCreateSocialUser(socialData);
        return done(null, { user, isNewUser } as unknown as Express.User);
      } catch (error) {
        return done(error as Error, null);
      }
    }
  )
);

// Serialize user for session
passport.serializeUser((user: Express.User, done) => {
  done(null, user);
});

// Deserialize user from session
passport.deserializeUser((user: Express.User, done) => {
  done(null, user);
});
