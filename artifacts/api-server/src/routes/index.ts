import { Router, type IRouter } from "express";
import auditRouter from "./audit";
import authRouter from "./auth";
import healthRouter from "./health";
import securityRouter from "./security";

const router: IRouter = Router();

router.use(healthRouter);
router.use(authRouter);
router.use(securityRouter);
router.use(auditRouter);

export default router;
