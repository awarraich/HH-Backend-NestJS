import { IsString, MaxLength, MinLength } from 'class-validator';

/**
 * Body for `POST /v1/api/documents/assignments/:assignmentId/reject`.
 * The reason is required (and surfaced verbatim in the employee's HR
 * File so they know what to fix), so this is intentionally not optional.
 */
export class RejectAssignmentDto {
  @IsString()
  @MinLength(1, { message: 'A rejection reason is required.' })
  @MaxLength(2000, { message: 'Rejection reason must be 2000 characters or fewer.' })
  reason: string;
}
