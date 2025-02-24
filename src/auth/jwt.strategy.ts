import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { jwtConstants } from './constants';

export type UserPayloadType = {
  userId: string;
  userEmail: string;
};

export type RequestWithUser = {
  user: UserPayloadType;
};

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: jwtConstants.secret || '',
      ignoreExpiration: false,
    });
  }

  validate({ userId, userEmail }: UserPayloadType) {
    return { userId, userEmail };
  }
}
