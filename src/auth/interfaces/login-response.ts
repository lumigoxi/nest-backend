import { UserPublic } from "./user-public";

export interface LoginResponse {
    user: UserPublic
    token: string;
}