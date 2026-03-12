import { IsInt, Min, Max, IsBoolean } from 'class-validator';

export class CreateInserviceQuizAttemptDto {
  @IsInt()
  @Min(0)
  @Max(100)
  score_percent: number;

  @IsBoolean()
  passed: boolean;
}
