// Note: Install @nestjs/bull and bull for full implementation
// npm install @nestjs/bull bull
//
// import { Injectable } from '@nestjs/common';
// import { InjectQueue } from '@nestjs/bull';
// import { Queue } from 'bull';
//
// @Injectable()
// export class VerificationMailJobProducer {
//   constructor(
//     @InjectQueue('verification-mail') private verificationMailQueue: Queue,
//   ) {}
//
//   async sendVerificationEmail(data: { email: string; token: string }) {
//     await this.verificationMailQueue.add('send-verification', data);
//   }
// }

// Placeholder export to prevent import errors
import { Injectable } from '@nestjs/common';

@Injectable()
export class VerificationMailJobProducer {
  sendVerificationEmail(_data: { email: string; token: string }): void {
    // Placeholder implementation
    console.log('Verification email job producer - install @nestjs/bull to enable');
  }
}
