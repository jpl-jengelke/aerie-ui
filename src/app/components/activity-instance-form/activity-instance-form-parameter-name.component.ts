import { CommonModule } from '@angular/common';
import {
  ChangeDetectionStrategy,
  Component,
  Input,
  NgModule,
} from '@angular/core';
import { ActivityInstanceFormParameter } from '../../types';

@Component({
  changeDetection: ChangeDetectionStrategy.OnPush,
  selector: 'parameter-name',
  styles: [
    `
      :host {
        align-items: center;
        display: flex;
      }

      div {
        color: rgba(0, 0, 0, 0.6);
        font-size: 14px;
        font-style: normal;
        font-weight: 500;
        letter-spacing: 0.1px;
        line-height: 24px;
        max-width: 100%;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }

      .error {
        color: red;
      }
    `,
  ],
  template: `
    <div [ngClass]="{ error: parameter.error }">
      {{ parameter.name }}
    </div>
  `,
})
export class ActivityInstanceFormParameterNameComponent {
  @Input()
  parameter: ActivityInstanceFormParameter | undefined;
}

@NgModule({
  declarations: [ActivityInstanceFormParameterNameComponent],
  exports: [ActivityInstanceFormParameterNameComponent],
  imports: [CommonModule],
})
export class ActivityInstanceFormParameterNameModule {}