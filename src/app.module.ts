import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import * as cookieParser from 'cookie-parser';
import { cookieExtractor } from './auth/strategies';

@Module({
  imports: [
    ConfigModule.forRoot({
    envFilePath: `.${process.env.NODE_ENV}.env`
  }),
    PrismaModule,
    AuthModule,
    
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
