import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';

export type AuthBody = { email: string; password: string };

@Injectable()
export class AuthService {
  constructor(private readonly prisma: PrismaService) {}

  async authenticate({ email, password }: AuthBody) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!existingUser) {
      throw new Error('User doesn’t exist');
    }

    if (existingUser.password !== password) {
      throw new Error('Invalid password');
    }

    return existingUser;
  }
}
