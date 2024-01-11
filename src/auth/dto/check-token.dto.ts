import { IsString, MinLength } from "class-validator";

export class CheckTokenDto {
    @IsString()
    @MinLength(20)
    token:string;
}
