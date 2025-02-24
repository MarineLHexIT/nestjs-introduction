import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UserPayloadType } from 'src/auth/jwt.strategy';

export type AuthBody = { email: string; password: string };

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async login({ email, password }: AuthBody) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!existingUser) {
      throw new Error('User doesn’t exist');
    }

    const isPasswordValid = await bcrypt.compare(
      password,
      existingUser.password,
    );

    if (!isPasswordValid) {
      throw new Error('Invalid password');
    }

    return this.authenticateUser(existingUser);
  }

  private authenticateUser(user: { id: string; email: string }) {
    const payload: UserPayloadType = {
      userId: user.id,
      userEmail: user.email,
    };
    return {
      accessToken: this.jwtService.sign(payload),
    };
  }

  private async hashPassword({ password }: { password: string }) {
    return await bcrypt.hash(password, 10);
  }
}
