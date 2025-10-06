import { Router } from 'express';
import { UserController } from '../controllers/userController.js';
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

export const userRoutes = router;
