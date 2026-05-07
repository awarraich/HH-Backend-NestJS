import { IsBoolean } from 'class-validator';

export class RespondMyScheduledWorkDto {
  @IsBoolean()
  accept: boolean;
}
