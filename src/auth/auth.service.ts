import { Injectable, UnauthorizedException, ConflictException } from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UserPayloadType } from 'src/auth/jwt.strategy';
import { CreateUserDto } from 'src/auth/dto/create-user.dto';
import { AuthenticateUserDto } from 'src/auth/dto/authenticate-user.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async login({ email, password }: AuthenticateUserDto) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!existingUser) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const isPasswordValid = await bcrypt.compare(
      password,
      existingUser.password,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid email or password');
    }

    return this.authenticateUser(existingUser);
  }

  async register({ email, firstName, lastName, password }: CreateUserDto) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      throw new ConflictException('Email already registered');
    }

    const hashedPassword = await this.hashPassword({ password });

    const newUser = await this.prisma.user.create({
      data: {
        email,
        firstName,
        lastName,
        password: hashedPassword,
      },
    });

    return this.authenticateUser(newUser);
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
