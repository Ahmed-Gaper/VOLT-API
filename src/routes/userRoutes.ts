import { Router } from 'express';
import { UserController } from '../controllers/userController.js';
import { authMiddleware, requireAuth } from '../middleware/authMiddleware.js';

const router = Router();

router.use(authMiddleware);
router.patch('/profile', requireAuth, UserController.updateProfile);
router.delete('/profile', requireAuth, UserController.deleteProfile);
router.post('/profile/picture', requireAuth, UserController.uploadProfilePicture);

export const userRoutes = router;
