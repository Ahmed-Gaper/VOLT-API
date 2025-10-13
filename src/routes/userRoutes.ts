import { Router } from 'express';
import { UserController } from '../controllers/userController.js';
import { FollowController } from '../controllers/followController.js';
import { authMiddleware, requireAuth } from '../middleware/authMiddleware.js';
import { upload } from '../middleware/uploadMiddleware.js';

const router = Router();

router.use(authMiddleware);
router.get('/profile', requireAuth, UserController.getProfile);
router.patch('/profile', requireAuth, UserController.updateProfile);
router.delete('/profile', requireAuth, UserController.deleteProfile);
router.post(
  '/profile/pictures',
  upload.array('profilePictures'),
  requireAuth,
  UserController.uploadProfilePictures
);

// Follow routes
router.post('/:userId/follow', requireAuth, FollowController.followUser);
router.delete('/:userId/unfollow', requireAuth, FollowController.unfollowUser);
router.get('/:userId/followers', FollowController.getFollowers);
router.get('/:userId/following', FollowController.getFollowing);

export const userRoutes = router;
