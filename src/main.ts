import { NestFactory } from '@nestjs/core';
import * as cookieParser from 'cookie-parser';
import { AppModule } from './app.module';

async function run() {
  try {
    const PORT = process.env.PORT || 3434
    const app = await NestFactory.create(AppModule);
    app.use(cookieParser())
    await app.listen(PORT, () => {
      console.log(`http://localhost:${PORT}`)
    });
  } catch (error) {
    console.log(error)
  }
}
run();
