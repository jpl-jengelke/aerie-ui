<svelte:options immutable={true} />

<script lang="ts">
  import { quadtree as d3Quadtree, type Quadtree } from 'd3-quadtree';
  import { scalePoint, type ScaleLinear, type ScalePoint, type ScaleTime } from 'd3-scale';
  import { curveLinear, line as d3Line } from 'd3-shape';
  import { createEventDispatcher, onMount, tick } from 'svelte';
  import type { Resource } from '../../types/simulation';
  import type { Axis, LinePoint, QuadtreePoint, ResourceLayerFilter, TimeRange } from '../../types/timeline';
  import { filterEmpty } from '../../utilities/generic';
  import { CANVAS_PADDING_Y, getYScale, searchQuadtreePoint } from '../../utilities/timeline';

  export let contextmenu: MouseEvent | undefined;
  export let dpr: number = 1;
  export let drawHeight: number = 0;
  export let drawWidth: number = 0;
  // TODO make an issue to remove these unneeded filters from LayerLine, LayerRange, etc
  export let filter: ResourceLayerFilter | undefined;
  export let id: number;
  export let lineColor: string = '';
  export let lineWidth: number = 1;
  export let mousemove: MouseEvent | undefined;
  export let mouseout: MouseEvent | undefined;
  export let pointRadius: number = 2;
  export let resources: Resource[] = [];
  export let showAsLinePlot: boolean = false;
  export let viewTimeRange: TimeRange = { end: 0, start: 0 };
  export let xScaleView: ScaleTime<number, number> | null = null;
  export let yAxes: Axis[] = [];
  export let yAxisId: number | null = null;

  const dispatch = createEventDispatcher();
  const WORK_TIME_THRESHOLD = 32; // ms to allow for processing time, beyond which remaining work will be split to a new frame

  let canvas: HTMLCanvasElement;
  let ctx: CanvasRenderingContext2D | null;
  let mounted: boolean = false;
  let quadtree: Quadtree<QuadtreePoint>;
  let scaleDomain: Set<string> = new Set();
  let visiblePointsById: Record<number, LinePoint> = {};
  let drawPointsRequest: number;
  let stateLinePlotYScale: ScalePoint<string>;
  let yScale: ScaleLinear<number, number, never>;
  let points: LinePoint[];
  let tempPoints: LinePoint[];
  let processingRequest: number;

  $: canvasHeightDpr = drawHeight * dpr;
  $: canvasWidthDpr = drawWidth * dpr;
  $: if (
    canvasHeightDpr &&
    canvasWidthDpr &&
    drawHeight &&
    drawWidth &&
    dpr &&
    // TODO swap filter out for resources which are recomputed when the view changes (i.e. filter changes)
    filter &&
    lineColor !== undefined &&
    typeof lineWidth === 'number' &&
    typeof pointRadius === 'number' &&
    mounted &&
    showAsLinePlot !== undefined &&
    points &&
    viewTimeRange &&
    xScaleView &&
    yAxes &&
    yAxisId !== undefined
  ) {
    draw();
  }
  $: onContextMenu(contextmenu);
  $: onMousemove(mousemove);
  $: onMouseout(mouseout);
  $: processResourcesToLinePoints(resources);
  $: offscreenPoint = ctx && generateOffscreenPoint(lineColor, pointRadius);

  onMount(() => {
    if (canvas) {
      ctx = canvas.getContext('2d');
    }
    mounted = true;
  });

  async function draw(): Promise<void> {
    if (ctx && xScaleView) {
      window.cancelAnimationFrame(drawPointsRequest);
      await tick();

      ctx.resetTransform();
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, drawWidth, drawHeight);

      const [yAxis] = yAxes.filter(axis => yAxisId === axis.id);

      quadtree = d3Quadtree<QuadtreePoint>()
        .x(p => p.x)
        .y(p => p.y)
        .extent([
          [0, 0],
          [drawWidth, drawHeight],
        ]);

      ctx.lineWidth = lineWidth;
      ctx.strokeStyle = lineColor;
      let line;

      if (showAsLinePlot) {
        const domain = Array.from(scaleDomain);
        stateLinePlotYScale = scalePoint()
          .domain(domain.filter(filterEmpty))
          .range([drawHeight - CANVAS_PADDING_Y, CANVAS_PADDING_Y]) as ScalePoint<string>;

        line = d3Line<LinePoint>()
          .x(d => (xScaleView as ScaleTime<number, number, never>)(d.x))
          .y(d => stateLinePlotYScale(d.y?.toString()) as number)
          .defined(d => d.y !== null) // Skip any gaps in resource data instead of interpolating
          .curve(curveLinear);
      } else {
        const domain = yAxis?.scaleDomain || [];
        yScale = getYScale(domain, drawHeight) as ScaleLinear<number, number, never>;

        line = d3Line<LinePoint>()
          .x(d => (xScaleView as ScaleTime<number, number, never>)(d.x))
          .y(d => yScale(d.y) as number)
          .defined(d => d.y !== null) // Skip any gaps in resource data instead of interpolating
          .curve(curveLinear);
      }

      ctx.beginPath();
      line.context(ctx)(points);
      ctx.stroke();
      ctx.closePath();

      drawPointsRequest = window.requestAnimationFrame(() => drawPoints());
    }
  }

  function drawPoints() {
    quadtree = d3Quadtree<QuadtreePoint>()
      .x(p => p.x)
      .y(p => p.y)
      .extent([
        [0, 0],
        [drawWidth, drawHeight],
      ]);
    visiblePointsById = {};

    if (!ctx || !offscreenPoint) {
      return;
    }

    for (const point of points) {
      if (point.x >= viewTimeRange.start && point.x <= viewTimeRange.end) {
        const x = (xScaleView as ScaleTime<number, number, never>)(point.x);
        let y: number;

        if (showAsLinePlot) {
          y = stateLinePlotYScale(point.y?.toString()) as number;
        } else {
          y = yScale(point.y) as number;
        }

        quadtree.add({ id: point.id, x, y });
        visiblePointsById[point.id] = point;
        ctx.drawImage(offscreenPoint, x - pointRadius, y - pointRadius, pointRadius * 2, pointRadius * 2);
      }
    }
  }

  function onContextMenu(e: MouseEvent | undefined): void {
    if (e) {
      dispatch('contextMenu', { e, origin: 'layer-line' });
    }
  }

  function onMousemove(e: MouseEvent | undefined): void {
    if (e) {
      const { offsetX: x, offsetY: y } = e;
      const points = searchQuadtreePoint<LinePoint>(quadtree, x, y, pointRadius, visiblePointsById);
      dispatch('mouseOver', { e, layerId: id, points });
    }
  }

  function onMouseout(e: MouseEvent | undefined): void {
    if (e) {
      dispatch('mouseOver', { e, layerId: id, points: [] });
    }
  }

  function processResourcesToLinePoints(resources: Resource[]) {
    if (typeof window === 'undefined') {
      return;
    }

    window.cancelAnimationFrame(processingRequest);

    points = [];
    tempPoints = [];

    processingRequest = window.requestAnimationFrame(() => resourcesToLinePoints(resources));
  }

  function resourcesToLinePoints(
    resources: Resource[],
    resourceStartIndex = 0,
    valueStartIndex = 0,
    startId = 0,
  ): void {
    const startTime = performance.now();
    let resourceIndex = resourceStartIndex;
    let valueIndex = valueStartIndex;
    let id = startId;

    for (resourceIndex; resourceIndex < resources.length; ++resourceIndex) {
      const resource = resources[resourceIndex];
      const { name, schema, values } = resource;

      if (schema.type === 'boolean') {
        for (valueIndex; valueIndex < values.length; ++valueIndex) {
          const value = values[valueIndex];
          const { x, y: yBoolean } = value;
          const y = yBoolean ? 1 : 0;
          tempPoints.push({
            id: id++,
            name,
            type: 'line',
            x,
            y,
          });

          if (performance.now() - startTime > WORK_TIME_THRESHOLD) {
            processingRequest = window.requestAnimationFrame(() =>
              resourcesToLinePoints(resources, resourceIndex, valueIndex + 1, id),
            );
            return;
          }
        }

        valueIndex = 0;
      } else if (
        schema.type === 'int' ||
        schema.type === 'real' ||
        (schema.type === 'struct' && schema?.items?.rate?.type === 'real' && schema?.items?.initial?.type === 'real')
      ) {
        for (valueIndex; valueIndex < values.length; ++valueIndex) {
          const value = values[valueIndex];
          const { x } = value;
          const y = value.y as number;
          tempPoints.push({
            id: id++,
            name,
            type: 'line',
            x,
            y,
          });

          if (performance.now() - startTime > WORK_TIME_THRESHOLD) {
            processingRequest = window.requestAnimationFrame(() =>
              resourcesToLinePoints(resources, resourceIndex, valueIndex + 1, id),
            );
            return;
          }
        }
        valueIndex = 0;
      } else if (schema.type === 'string' || schema.type === 'variant') {
        for (let i = 0; i < values.length; ++i) {
          const value = values[i];
          const { x } = value;
          const y = value.y as number;
          scaleDomain.add(value.y as string);
          tempPoints.push({
            id: id++,
            name,
            type: 'line',
            x,
            y,
          });

          if (performance.now() - startTime > WORK_TIME_THRESHOLD) {
            processingRequest = window.requestAnimationFrame(() =>
              resourcesToLinePoints(resources, resourceIndex, valueIndex + 1, id),
            );
            return;
          }
        }
        valueIndex = 0;
      }
    }

    points = tempPoints;
  }

  function generateOffscreenPoint(lineColor: string, radius: number): OffscreenCanvas | HTMLCanvasElement | null {
    if (!radius) {
      return null;
    }

    let tempCanvas: OffscreenCanvas | HTMLCanvasElement;
    let tempCtx: CanvasRenderingContext2D | OffscreenCanvasRenderingContext2D | null;

    if ('OffscreenCanvas' in window) {
      tempCanvas = new OffscreenCanvas(radius * 2 * dpr, radius * 2 * dpr);
    } else {
      tempCanvas = document.createElement('canvas');
      tempCanvas.height = radius * 2 * dpr;
      tempCanvas.width = radius * 2 * dpr;
      tempCanvas.style.height = `${radius * 2}px`;
      tempCanvas.style.width = `${radius * 2}px`;
    }

    tempCtx = tempCanvas.getContext('2d');

    if (!tempCtx) {
      return null;
    }

    tempCtx.resetTransform();
    tempCtx.scale(dpr, dpr);
    tempCtx.fillStyle = lineColor;

    const circle = new Path2D();
    circle.arc(radius, radius, radius, 0, 2 * Math.PI);
    tempCtx.fill(circle);

    return tempCanvas;
  }
</script>

<canvas
  bind:this={canvas}
  height={canvasHeightDpr}
  id={`layer-line-${id}`}
  style="height: {drawHeight}px; width: {drawWidth}px;"
  width={canvasWidthDpr}
  on:contextmenu={onContextMenu}
/>

<style>
  canvas {
    position: absolute;
    z-index: -1;
  }
</style>
