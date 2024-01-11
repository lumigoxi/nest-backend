import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { JwtPayload } from '../interfaces/payload-jwt';
import { AuthService } from '../auth.service';
import { UserPublic } from '../interfaces/user-public';

@Injectable()
export class AuthGuard implements CanActivate {

    constructor(
        private jwtService:JwtService,
        private authService: AuthService
        ){}

    async canActivate( context: ExecutionContext ): Promise<boolean> {

        const request = context.switchToHttp().getRequest();
        const token = this.extractTokenFromHeader(request);
        
        if( !token ) throw new UnauthorizedException();

        let user:UserPublic;

        try {
            const payload = await this.jwtService.verifyAsync<JwtPayload>(token, { secret: process.env['JWT_SEED'] });
            user = await this.authService.findUserById(payload.id);
        } catch (error) {
            throw new UnauthorizedException();
        }
        
        if( !user ) throw new UnauthorizedException('No existe el usuario');
        if( !user.isActive ) throw new UnauthorizedException('Usuario inactivo');

        request['user'] = user;

        return true;
    }

    private extractTokenFromHeader = (request: Request) => {
        const [type, token] = request.headers['authorization']?.split(' ') ?? [];
        return type === 'Bearer' ? token : null;
    }
}
