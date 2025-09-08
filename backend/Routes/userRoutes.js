import express from 'express';
import { register,login,logout,getUser,updatePassword,updateProfile,googleAuth,checkMobile} from '../controllers/userController.js'; 
import { isAuthenticated, isAuthorized } from "../middleware/auth.js";
const router =express.Router();
router.post('/register',register);
router.post("/login",login);
router.post("/logout",logout);
router.post("/auth/google",googleAuth);
router.get("/check-mobile",checkMobile);


router.get("/get-me",isAuthenticated,getUser);
router.put("/update-password",isAuthenticated,updatePassword);
router.put("/update-profile",isAuthenticated,updateProfile);


export default router;
