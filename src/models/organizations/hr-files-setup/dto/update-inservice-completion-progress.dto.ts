import { IsInt, Min, Max } from 'class-validator';

export class UpdateInserviceCompletionProgressDto {
  @IsInt()
  @Min(0)
  @Max(100)
  progress_percent: number;
}
