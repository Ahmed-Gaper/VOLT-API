import { Router } from 'express';
import { UserController } from '../controllers/userController.js';
import { FollowController } from '../controllers/followController.js';
import { authMiddleware, requireAuth } from '../middleware/authMiddleware.js';
import { upload } from '../middleware/uploadMiddleware.js';
import { blockCheck } from '../middleware/blockCheck.js';
import { BlockController } from '../controllers/blockController.js';

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
router.get('/:userId/blocked', requireAuth, BlockController.getBlocked);

router.get('/search', requireAuth, UserController.search);
router.get('/:userId', UserController.getUserProfile);

// Follow routes
router.post('/:userId/follow', requireAuth, blockCheck, FollowController.followUser);
router.delete('/:userId/unfollow', requireAuth, blockCheck, FollowController.unfollowUser);
router.get('/:userId/followers', blockCheck, FollowController.getFollowers);
router.get('/:userId/following', blockCheck, FollowController.getFollowing);

// Block routes

router.post('/:userId/block', requireAuth, BlockController.blockUser);
router.delete('/:userId/block', requireAuth, BlockController.unblockUser);

export default router;

export const userRoutes = router;
