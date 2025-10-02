import { Router } from 'express';
import { UserController } from '../controllers/userController.js';
import { authMiddleware, requireAuth } from '../middleware/authMiddleware.js';
import { upload } from '../middleware/uploadMiddleware.js';

const router = Router();

router.use(authMiddleware);
router.patch('/profile', requireAuth, UserController.updateProfile);
router.delete('/profile', requireAuth, UserController.deleteProfile);
router.post(
  '/profile/picture',
  upload.single('profilePicture'),
  requireAuth,
  UserController.uploadProfilePicture
);

export const userRoutes = router;
