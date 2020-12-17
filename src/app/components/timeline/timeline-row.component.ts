import { CommonModule } from '@angular/common';
import {
  AfterViewInit,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  Component,
  ElementRef,
  EventEmitter,
  Input,
  NgModule,
  OnChanges,
  OnDestroy,
  Output,
  ViewChild,
} from '@angular/core';
import { ScaleTime } from 'd3-scale';
import {
  getTimeFromSvgMousePosition,
  getTooltipTextForPoints,
  hideTooltip,
  showTooltip,
} from '../../functions';
import {
  ActivityPoint,
  Axis,
  CreatePoint,
  DeletePoint,
  HorizontalGuide,
  HorizontalGuideEvent,
  Layer,
  LinePoint,
  MouseOverPoints,
  MouseSelectPoints,
  SavePoint,
  SelectPoint,
  TimeRange,
  UpdatePoint,
  UpdateRow,
  XAxisTick,
  XRangePoint,
} from '../../types';
import { TimelineRowHorizontalGuidesModule } from './timeline-row-horizontal-guides.component';
import { TimelineRowLayerActivityModule } from './timeline-row-layer-activity.component';
import { TimelineRowLayerLineModule } from './timeline-row-layer-line.component';
import { TimelineRowLayerXRangeModule } from './timeline-row-layer-x-range.component';
import { TimelineRowMenuModule } from './timeline-row-menu.component';
import { TimelineRowXAxisTicksModule } from './timeline-row-x-axis-ticks.component';
import { TimelineRowYAxesModule } from './timeline-row-y-axes.component';

@Component({
  changeDetection: ChangeDetectionStrategy.OnPush,
  selector: 'aerie-timeline-row',
  styles: [
    `
      .container {
        background: white;
        border-bottom: 1px solid lightgrey;
        display: block;
        position: relative;
        width: 100%;
        z-index: 0;
      }

      .axis-container,
      .overlay-container,
      .row-container {
        cursor: pointer;
        height: inherit;
        position: absolute;
        width: inherit;
      }

      .axis-container {
        z-index: -1;
      }

      .overlay-container {
        z-index: 2;
      }

      .row-container {
        z-index: 1;
      }
    `,
  ],
  template: `
    <div class="container" [attr.style]="'height:' + height + 'px;'">
      <svg
        #overlay
        class="overlay-container"
        [ngStyle]="{
          height: drawHeight + 'px',
          transform: 'translate(' + marginLeft + 'px ,' + marginTop + 'px)',
          width: drawWidth + 'px'
        }"
      >
        <g
          aerie-timeline-row-horizontal-guides
          [drawHeight]="drawHeight"
          [drawWidth]="drawWidth"
          [horizontalGuides]="horizontalGuides"
          [yAxes]="yAxes"
        ></g>
      </svg>

      <div
        class="row-container"
        [ngStyle]="{
          height: drawHeight + 'px',
          transform: 'translate(' + marginLeft + 'px ,' + marginTop + 'px)',
          width: drawWidth + 'px'
        }"
      >
        <ng-container *ngFor="let layer of layers; trackBy: trackByLayers">
          <aerie-timeline-row-layer-activity
            *ngIf="layer.chartType === 'activity'"
            [color]="layer.color"
            [dragenter]="dragenter"
            [dragleave]="dragleave"
            [dragover]="dragover"
            [drop]="drop"
            [drawHeight]="drawHeight"
            [drawWidth]="drawWidth"
            [height]="height"
            [id]="layer.id"
            [maxTimeRange]="maxTimeRange"
            [mousedown]="mousedown"
            [mousemove]="mousemove"
            [mouseout]="mouseout"
            [mouseup]="mouseup"
            [overlay]="overlay"
            [points]="layer.points"
            [rowId]="id"
            [viewTimeRange]="viewTimeRange"
            [xScaleView]="xScaleView"
            (mouseOverPoints)="onMouseOverPoints($event)"
            (mouseSelectPoints)="onMouseSelectPoints($event)"
            (createPoint)="createPoint.emit($event)"
            (savePoint)="savePoint.emit($event)"
            (updatePoint)="updatePoint.emit($event)"
            (updateRow)="onUpdateRow($event)"
          ></aerie-timeline-row-layer-activity>
          <aerie-timeline-row-layer-line
            *ngIf="layer.chartType === 'line'"
            [color]="layer.color"
            [drawHeight]="drawHeight"
            [drawWidth]="drawWidth"
            [id]="layer.id"
            [maxTimeRange]="maxTimeRange"
            [mousemove]="mousemove"
            [mouseout]="mouseout"
            [points]="layer.points"
            [viewTimeRange]="viewTimeRange"
            [xScaleView]="xScaleView"
            [yAxes]="yAxes"
            [yAxisId]="layer.yAxisId"
            (mouseOverPoints)="onMouseOverPoints($event)"
          ></aerie-timeline-row-layer-line>
          <aerie-timeline-row-layer-x-range
            *ngIf="layer.chartType === 'x-range'"
            [drawHeight]="drawHeight"
            [drawWidth]="drawWidth"
            [id]="layer.id"
            [maxTimeRange]="maxTimeRange"
            [mousemove]="mousemove"
            [mouseout]="mouseout"
            [points]="layer.points"
            [viewTimeRange]="viewTimeRange"
            [xScaleView]="xScaleView"
            (mouseOverPoints)="onMouseOverPoints($event)"
          ></aerie-timeline-row-layer-x-range>
        </ng-container>
      </div>

      <aerie-timeline-row-x-axis-ticks
        [drawHeight]="drawHeight"
        [marginLeft]="marginLeft"
        [marginTop]="marginTop"
        [xScaleView]="xScaleView"
        [xTicksView]="xTicksView"
      ></aerie-timeline-row-x-axis-ticks>

      <aerie-timeline-row-y-axes
        [drawHeight]="drawHeight"
        [marginLeft]="marginLeft"
        [marginTop]="marginTop"
        [yAxes]="yAxes"
      ></aerie-timeline-row-y-axes>

      <aerie-timeline-row-menu
        [horizontalGuides]="horizontalGuides"
        (createHorizontalGuide)="onCreateHorizontalGuide()"
        (deleteHorizontalGuide)="deleteHorizontalGuide.emit($event)"
        (updateHorizontalGuide)="onUpdateHorizontalGuide($event)"
      ></aerie-timeline-row-menu>
    </div>
  `,
})
export class TimelineRowComponent
  implements AfterViewInit, OnChanges, OnDestroy {
  @Input()
  autoAdjustHeight: boolean | undefined;

  @Input()
  drawWidth: number;

  @Input()
  height = 200;

  @Input()
  horizontalGuides: HorizontalGuide[] | undefined;

  @Input()
  id: string;

  @Input()
  layers: Layer[];

  @Input()
  marginLeft: number;

  @Input()
  marginRight: number;

  @Input()
  maxTimeRange: TimeRange;

  @Input()
  viewTimeRange: TimeRange;

  @Input()
  xScaleView: ScaleTime<number, number>;

  @Input()
  xTicksView: XAxisTick[] = [];

  @Input()
  yAxes: Axis[] | undefined;

  @Output()
  createHorizontalGuide: EventEmitter<HorizontalGuideEvent> = new EventEmitter<HorizontalGuideEvent>();

  @Output()
  createPoint: EventEmitter<CreatePoint> = new EventEmitter<CreatePoint>();

  @Output()
  deleteHorizontalGuide: EventEmitter<HorizontalGuide> = new EventEmitter<HorizontalGuide>();

  @Output()
  deletePoint: EventEmitter<DeletePoint> = new EventEmitter<DeletePoint>();

  @Output()
  savePoint: EventEmitter<SavePoint> = new EventEmitter<SavePoint>();

  @Output()
  selectPoint: EventEmitter<SelectPoint> = new EventEmitter<SelectPoint>();

  @Output()
  updateHorizontalGuide: EventEmitter<HorizontalGuideEvent> = new EventEmitter<HorizontalGuideEvent>();

  @Output()
  updatePoint: EventEmitter<UpdatePoint> = new EventEmitter<UpdatePoint>();

  @Output()
  updateRow: EventEmitter<UpdateRow> = new EventEmitter<UpdateRow>();

  @ViewChild('overlay', { static: true })
  overlay: ElementRef<SVGElement>;

  dragenter: DragEvent;
  dragenterListener: (dragenter: DragEvent) => void;
  dragleave: DragEvent;
  dragleaveListener: (dragleave: DragEvent) => void;
  dragover: DragEvent;
  dragoverListener: (dragover: DragEvent) => void;
  drop: DragEvent;
  dropListener: (drop: DragEvent) => void;
  mousedown: MouseEvent;
  mousedownListener: (mouseout: MouseEvent) => void;
  mousemove: MouseEvent;
  mousemoveListener: (mousemove: MouseEvent) => void;
  mouseout: MouseEvent;
  mouseoutListener: (mouseout: MouseEvent) => void;
  mouseup: MouseEvent;
  mouseupListener: (mouseout: MouseEvent) => void;

  drawHeight: number;
  marginBottom = 2;
  marginTop = 2;

  constructor(private cdRef: ChangeDetectorRef) {}

  ngOnChanges(): void {
    this.setHeight();
  }

  ngAfterViewInit(): void {
    this.initEventListeners();
    this.setHeight();
  }

  ngOnDestroy(): void {
    this.destroyEventListeners();
  }

  destroyEventListeners() {
    const overlay = this.overlay.nativeElement;
    overlay.removeEventListener('dragenter', this.dragenterListener);
    overlay.removeEventListener('dragleave', this.dragleaveListener);
    overlay.removeEventListener('dragover', this.dragoverListener);
    overlay.removeEventListener('drop', this.dropListener);
    overlay.removeEventListener('mousedown', this.mousedownListener);
    overlay.removeEventListener('mousemove', this.mousemoveListener);
    overlay.removeEventListener('mouseout', this.mouseoutListener);
    overlay.removeEventListener('mouseup', this.mouseupListener);
  }

  initEventListeners() {
    const { nativeElement: overlay } = this.overlay;

    // dragenter
    this.dragenterListener = (dragenter: DragEvent) => {
      dragenter.preventDefault();
      this.dragenter = dragenter;
      this.cdRef.detectChanges();
    };
    overlay.addEventListener('dragenter', this.dragenterListener);

    // dragleave
    this.dragleaveListener = (dragleave: DragEvent) => {
      this.dragleave = dragleave;
      this.cdRef.detectChanges();
    };
    overlay.addEventListener('dragleave', this.dragleaveListener);

    // dragover
    this.dragoverListener = (dragover: DragEvent) => {
      dragover.preventDefault();
      this.dragover = dragover;
      this.cdRef.detectChanges();
    };
    overlay.addEventListener('dragover', this.dragoverListener);

    // drop.
    this.dropListener = (drop: DragEvent) => {
      drop.preventDefault();
      this.drop = drop;
      this.cdRef.detectChanges();
    };
    overlay.addEventListener('drop', this.dropListener);

    // mousedown.
    this.mousedownListener = (mousedown: MouseEvent) => {
      this.mousedown = mousedown;
      this.cdRef.detectChanges();
    };
    overlay.addEventListener('mousedown', this.mousedownListener);

    // mousemove.
    this.mousemoveListener = (mousemove: MouseEvent) => {
      this.mousemove = mousemove;
      this.cdRef.detectChanges();
    };
    overlay.addEventListener('mousemove', this.mousemoveListener);

    // mouseout.
    this.mouseoutListener = (mouseout: MouseEvent) => {
      this.mouseout = mouseout;
      this.cdRef.detectChanges();
    };
    overlay.addEventListener('mouseout', this.mouseoutListener);

    // mouseup.
    this.mouseupListener = (mouseup: MouseEvent) => {
      this.mouseup = mouseup;
      this.cdRef.detectChanges();
    };
    overlay.addEventListener('mouseup', this.mouseupListener);
  }

  onCreateHorizontalGuide() {
    const event: HorizontalGuideEvent = {
      mode: 'create',
      rowId: this.id,
      yAxes: this.yAxes,
    };
    this.createHorizontalGuide.emit(event);
  }

  onUpdateHorizontalGuide(guide: HorizontalGuide) {
    const event: HorizontalGuideEvent = {
      guide,
      mode: 'edit',
      rowId: this.id,
      yAxes: this.yAxes,
    };
    this.updateHorizontalGuide.emit(event);
  }

  onMouseOverPoints(event: MouseOverPoints<LinePoint | XRangePoint>) {
    if (event.points.length) {
      const { doyTimestamp } = getTimeFromSvgMousePosition(
        this.overlay.nativeElement,
        event.e,
        this.xScaleView,
      );
      let tooltipText = `${doyTimestamp}<br>`;
      if (event.points.length) {
        tooltipText += getTooltipTextForPoints(event.points);
      }
      showTooltip(event.e, tooltipText, this.drawWidth);
    } else {
      hideTooltip();
    }
  }

  onMouseSelectPoints(event: MouseSelectPoints<ActivityPoint>) {
    if (event.points.length) {
      const [point] = event.points;
      this.selectPoint.emit({ id: point.id, type: point.type });
    }
  }

  onUpdateRow(event: UpdateRow) {
    if (this.autoAdjustHeight === undefined || this.autoAdjustHeight === true) {
      this.updateRow.emit(event);
    }
  }

  setHeight() {
    this.drawHeight = this.height - this.marginTop - this.marginBottom;
  }

  trackByLayers(_: number, layer: Layer) {
    return layer.id;
  }
}

@NgModule({
  declarations: [TimelineRowComponent],
  exports: [TimelineRowComponent],
  imports: [
    CommonModule,
    TimelineRowHorizontalGuidesModule,
    TimelineRowLayerActivityModule,
    TimelineRowLayerLineModule,
    TimelineRowLayerXRangeModule,
    TimelineRowMenuModule,
    TimelineRowXAxisTicksModule,
    TimelineRowYAxesModule,
  ],
})
export class TimelineRowModule {}