import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as byCrypt from "bcryptjs";

import { CreateUserDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';

import { User } from './entities/user.entity';
import { LoginUserDto } from './dto/login--user.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/payload-jwt';
import { LoginResponse } from './interfaces/login-response';
import { UserPublic } from './interfaces/user-public';


@Injectable()
export class AuthService {

    private ERROR_CODE_DUPLICATE_EMAIL = 11000;

    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
        private jwtService: JwtService
    ) { }

    async create(createUserDto: CreateUserDto): Promise<UserPublic> {
        
        try {

            const { password, ...userData } = createUserDto;
            const user = new this.userModel({
                ...userData,
                password: byCrypt.hashSync(password, 10)
            });

            await user.save();

            return this._getPublicUser(user.toJSON());

        } catch (error) {
            
            if (error.code === this.ERROR_CODE_DUPLICATE_EMAIL)
                throw new BadRequestException(`${createUserDto.email} already exist`);

            throw new InternalServerErrorException('DEAD')
        }

    }

    async login(loginUserDto: LoginUserDto): Promise<LoginResponse> {

        const { email, password } = loginUserDto;
        const user = await this.userModel.findOne({ email });
        
        if (!user )
            throw new UnauthorizedException('Login invalido (user)')

        if( !byCrypt.compareSync(password, user.password) )
            throw new UnauthorizedException('Login invalido (password)')

        const userPublic = this._getPublicUser(user.toJSON());

        return {
            user: userPublic,
            token: this.getJwt({ id: user.id, })
        }

    }

    async register(createUserDto: CreateUserDto): Promise<LoginResponse> {
        
        const user = await this.create(createUserDto);
        
        return {
            user,
            token: this.getJwt({id: user._id})
        };
    }

    findAll() {
        return this.userModel.find();
    }

    async findUserById(id: string):Promise<UserPublic|null>{

        const user = (await this.userModel.findById(id));
        
        if( !user ) return null;

        return this._getPublicUser(user.toJSON());
    }

    findOne(id: number) {
        return `This action returns a #${id} auth`;
    }

    update(id: number, updateAuthDto: UpdateAuthDto) {
        return `This action updates a #${id} auth`;
    }

    remove(id: number) {
        return `This action removes a #${id} auth`;
    }

    checkToken(_user:User):LoginResponse{
        
        const user = this._getPublicUser(_user);

        return {
            user,
            token: this.getJwt({ id: user._id, })
        }
    }

    private getJwt = (payload: JwtPayload) => this.jwtService.sign(payload)

    private _getPublicUser = (_user:User) => {
        const {password, ...user} = _user;
        return user;
    }

}
