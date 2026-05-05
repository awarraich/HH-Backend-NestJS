import { IsBoolean } from 'class-validator';

export class RespondMyShiftDto {
  @IsBoolean()
  accept: boolean;
}
