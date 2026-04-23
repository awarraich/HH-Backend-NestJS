import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserOAuthAccount } from '../../../authentication/entities/user-oauth-account.entity';
import { ZoomService } from './zoom.service';
import { GoogleMeetService } from './google-meet.service';
import { InterviewMeetingService } from './interview-meeting.service';

@Module({
  imports: [TypeOrmModule.forFeature([UserOAuthAccount])],
  providers: [ZoomService, GoogleMeetService, InterviewMeetingService],
  exports: [ZoomService, GoogleMeetService, InterviewMeetingService],
})
export class MeetingIntegrationModule {}
