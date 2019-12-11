import {
  AfterViewInit,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  Component,
  ElementRef,
  HostListener,
  OnDestroy,
} from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { select, Store } from '@ngrx/store';
import { SubSink } from 'subsink';
import { MerlinActions } from '../../actions';
import { AppState } from '../../app-store';
import {
  getActivityInstancesForSelectedPlan,
  getActivityTypes,
  getActivityTypesMap,
  getSelectedActivityInstance,
  getSelectedPlan,
} from '../../selectors';
import {
  CActivityInstance,
  CActivityType,
  CActivityTypeMap,
  CPlan,
  SActivityInstance,
  UpdateActivityInstance,
} from '../../types';

@Component({
  changeDetection: ChangeDetectionStrategy.OnPush,
  selector: 'app-plan',
  styleUrls: ['./plan.component.css'],
  templateUrl: './plan.component.html',
})
export class PlanComponent implements AfterViewInit, OnDestroy {
  activityInstances: CActivityInstance[] | null = null;
  activityTypes: CActivityType[] | null = null;
  activityTypesMap: CActivityTypeMap | null = null;
  bottomPanelHeight = 200;
  panels = {
    activityInstances: {
      order: 2,
      size: 50,
      visible: true,
    },
    activityTypes: {
      order: 0,
      size: 20,
      visible: true,
    },
    bottom: {
      order: 1,
      size: 40,
      visible: true,
    },
    createActivityInstance: {
      order: 1,
      size: 20,
      visible: true,
    },
    selectedActivityInstance: {
      order: 3,
      size: 20,
      visible: true,
    },
    top: {
      order: 0,
      size: 60,
      visible: true,
    },
  };
  plan: CPlan | null = null;
  selectedActivityInstance: CActivityInstance | null = null;

  private subs = new SubSink();

  constructor(
    private cdRef: ChangeDetectorRef,
    private elRef: ElementRef,
    private route: ActivatedRoute,
    private store: Store<AppState>,
  ) {
    this.subs.add(
      this.store
        .pipe(select(getActivityInstancesForSelectedPlan))
        .subscribe(activityInstances => {
          this.activityInstances = activityInstances;
          this.cdRef.markForCheck();
        }),
      this.store.pipe(select(getActivityTypes)).subscribe(activityTypes => {
        this.activityTypes = activityTypes;
        this.cdRef.markForCheck();
      }),
      this.store
        .pipe(select(getActivityTypesMap))
        .subscribe(activityTypesMap => {
          this.activityTypesMap = activityTypesMap;
          this.cdRef.markForCheck();
        }),
      this.store
        .pipe(select(getSelectedActivityInstance))
        .subscribe(selectedActivityInstance => {
          this.selectedActivityInstance = selectedActivityInstance;
          this.cdRef.markForCheck();
        }),
      this.store.pipe(select(getSelectedPlan)).subscribe(plan => {
        this.plan = plan;
        this.cdRef.markForCheck();
      }),
    );
  }

  ngAfterViewInit() {
    this.setBottomPanelHeight();
  }

  ngOnDestroy(): void {
    this.subs.unsubscribe();
  }

  onCreateActivityInstance(activityInstance: SActivityInstance): void {
    const { id: planId } = this.route.snapshot.params;
    this.store.dispatch(
      MerlinActions.createActivityInstance({ planId, activityInstance }),
    );
  }

  onDeleteActivityInstance(activityInstanceId: string): void {
    const { id: planId } = this.route.snapshot.params;
    this.store.dispatch(
      MerlinActions.deleteActivityInstance({ planId, activityInstanceId }),
    );
  }

  onResize(): void {
    this.store.dispatch(MerlinActions.resize());
    this.setBottomPanelHeight();
  }

  onSelectActivityInstance(activityInstance: CActivityInstance): void {
    this.store.dispatch(
      MerlinActions.setSelectedActivityInstanceId({
        selectedActivityInstanceId: activityInstance.id,
      }),
    );
  }

  onUpdateActivityInstance(update: UpdateActivityInstance): void {
    const { id: planId } = this.route.snapshot.params;
    const { activityInstanceId, activityInstance } = update;
    this.store.dispatch(
      MerlinActions.updateActivityInstance({
        activityInstance,
        activityInstanceId,
        planId,
      }),
    );
  }

  @HostListener('window:resize', ['$event'])
  onWindowResize() {
    this.setBottomPanelHeight();
  }

  setBottomPanelHeight() {
    const bottomPanel = this.elRef.nativeElement.querySelector('.bottom-panel');
    if (bottomPanel) {
      this.bottomPanelHeight = bottomPanel.clientHeight;
    }
  }

  togglePanelVisible(panel: string): void {
    this.panels[panel].visible = !this.panels[panel].visible;
  }
}
