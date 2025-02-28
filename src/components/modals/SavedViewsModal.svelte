<svelte:options immutable={true} />

<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import { SearchParameters } from '../../enums/searchParameters';
  import { initializeView, view, views } from '../../stores/views';
  import type { User } from '../../types/app';
  import type { View, ViewSlim } from '../../types/view';
  import effects from '../../utilities/effects';
  import { setQueryParam } from '../../utilities/generic';
  import { downloadView as downloadViewUtil } from '../../utilities/view';
  import Tab from '../ui/Tabs/Tab.svelte';
  import TabPanel from '../ui/Tabs/TabPanel.svelte';
  import Tabs from '../ui/Tabs/Tabs.svelte';
  import ViewsTable from '../view/ViewsTable.svelte';
  import Modal from './Modal.svelte';
  import ModalContent from './ModalContent.svelte';
  import ModalHeader from './ModalHeader.svelte';

  export let height: number | string = 150;
  export let width: number | string = 380;
  export let user: User | null;

  const dispatch = createEventDispatcher();

  let userViews: ViewSlim[] = [];

  $: userViews = $views.filter((view: ViewSlim) => view.owner === user?.id);

  async function deleteView({ detail: viewId }: CustomEvent<number>) {
    const matchingView = $views.find(v => v.id === viewId);
    if (matchingView) {
      const success = await effects.deleteView(matchingView, user);

      if (success) {
        if ($view?.id === viewId) {
          goToNextView();
        }
      }
    }
  }

  async function deleteViews({ detail: viewIds }: CustomEvent<number[]>) {
    const matchingViews = $views.filter(v => viewIds.some(viewId => viewId === v.id));
    const success = await effects.deleteViews(matchingViews, user);

    if (success) {
      if ($view && viewIds.includes($view.id)) {
        goToNextView();
      }
    }
  }

  async function goToNextView() {
    const nextView = await effects.getView(null, user);
    if (nextView !== null) {
      initializeView({ ...nextView });
      setQueryParam(SearchParameters.VIEW_ID, `${nextView.id}`);
    }
  }

  async function getFullView(viewId: number): Promise<View | null> {
    const query = new URLSearchParams(`?${SearchParameters.VIEW_ID}=${viewId}`);
    return await effects.getView(query, user);
  }

  async function openView({ detail: viewId }: CustomEvent<number>) {
    const view = await getFullView(viewId);
    if (view !== null) {
      initializeView({ ...view });
      setQueryParam(SearchParameters.VIEW_ID, `${view.id}`);
      dispatch('close');
    } else {
      console.log(`No view found for ID: ${viewId}`);
    }
  }

  async function downloadView({ detail: viewId }: CustomEvent<number>) {
    const view = await getFullView(viewId);
    if (view !== null) {
      downloadViewUtil(view);
      dispatch('close');
    } else {
      console.log(`No view found for ID: ${viewId}`);
    }
  }
</script>

<Modal {height} {width}>
  <ModalHeader on:close>Saved Views</ModalHeader>
  <ModalContent style="padding:0">
    <Tabs class="view-tabs" tabListClassName="view-tabs-list">
      <svelte:fragment slot="tab-list">
        <Tab class="view-tab">All Views</Tab>
        <Tab class="view-tab">My Views</Tab>
      </svelte:fragment>
      <TabPanel>
        <ViewsTable
          {user}
          views={$views}
          on:deleteView={deleteView}
          on:deleteViews={deleteViews}
          on:openView={openView}
          on:downloadView={downloadView}
        />
      </TabPanel>
      <TabPanel>
        <ViewsTable
          {user}
          views={userViews}
          on:deleteView={deleteView}
          on:deleteViews={deleteViews}
          on:openView={openView}
          on:downloadView={downloadView}
        />
      </TabPanel>
    </Tabs>
  </ModalContent>
</Modal>

<style>
  :global(.view-tabs) {
    padding: 0 1rem 1rem;
  }

  :global(.view-tab) {
    --tab-background-color: var(--st-white);
    --tab-hover-background-color: var(--st-white);
    --tab-hover-text-color: var(--st-gray-70);
    --tab-padding: 0px;
    --tab-selected-background-color: var(--st-white);
    --tab-text-color: var(--st-gray-50);
  }

  :global(.view-tabs-list) {
    --tab-list-background-color: var(--st-white);
    --tab-list-gap: 8px;
    border-bottom: 1px solid var(--st-gray-15);
    width: 100%;
  }
</style>
