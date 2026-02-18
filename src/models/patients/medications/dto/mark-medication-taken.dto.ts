import { IsString, IsNotEmpty, IsDateString, MaxLength } from 'class-validator';

export class MarkMedicationTakenDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(20)
  timeSlot: string;

  @IsString()
  @IsNotEmpty()
  @IsDateString()
  date: string;
}
