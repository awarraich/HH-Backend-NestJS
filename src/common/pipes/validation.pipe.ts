import { PipeTransform, Injectable, ArgumentMetadata, BadRequestException } from '@nestjs/common';

// Note: For full validation, install class-validator and class-transformer
// npm install class-validator class-transformer
@Injectable()
export class ValidationPipe implements PipeTransform<any> {
  transform(value: unknown, _metadata: ArgumentMetadata) {
    // Basic validation - extend this with class-validator for full validation
    if (!value) {
      throw new BadRequestException('Validation failed: value is required');
    }
    return value;
  }
}
