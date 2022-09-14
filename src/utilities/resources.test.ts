import { describe, expect, test } from 'vitest';
import { sampleProfiles } from './resources';

describe('sampleProfiles', () => {
  test('calculate the correct y-value for real profile segment rate of change', () => {
    const profiles: Profile[] = [
      {
        name: '/simple_data/b/volume',
        profile_segments: [
          {
            dynamics: { initial: 0, rate: 0 },
            start_offset: '00:00:00',
          },
          {
            dynamics: { initial: 0, rate: 5 },
            start_offset: '2 days 19:40:54.345',
          },
          {
            dynamics: { initial: 566834.75, rate: 0 },
            start_offset: '4 days 03:10:21.295',
          },
        ],
        type: {
          schema: {
            items: { initial: { type: 'real' }, rate: { type: 'real' } },
            type: 'struct',
          },
          type: 'real',
        },
      },
    ];

    const resources: Resource[] = sampleProfiles(profiles, '2022-09-01T00:00:00+00:00', '384:00:00');

    const expectedResources: Resource[] = [
      {
        name: '/simple_data/b/volume',
        schema: {
          items: { initial: { type: 'real' }, rate: { type: 'real' } },
          type: 'struct',
        },
        values: [
          { x: 1661990400000, y: 0 },
          { x: 1662234054345, y: 0 },
          { x: 1662234054345, y: 0 },
          { x: 1662347421295, y: 566834.75 },
          { x: 1662347421295, y: 566834.75 },
          { x: 1663372800000, y: 566834.75 },
        ],
      },
    ];

    expect(resources).toEqual(expectedResources);
  });
});