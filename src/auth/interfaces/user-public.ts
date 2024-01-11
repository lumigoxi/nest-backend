import { User } from "../entities/user.entity";

export interface UserPublic extends Omit<User, 'password'>{}