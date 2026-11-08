<template>
  <div class="y-page">
    <PageHeader
      :eyebrow="$t('shell.adminArea')"
      :title="$t('uiAdmin1.domains.title')"
      :description="$t('uiAdmin1.domains.description')"
    >
      <template #actions>
        <button type="button" class="btn btn-primary gap-2" @click="openCreateModal">
          <Plus :size="16" :stroke-width="1.5" />
          {{ $t('adminDomains.addDomain') }}
        </button>
      </template>
    </PageHeader>

    <!-- Status stats double as filters -->
    <section class="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
      <button
        v-for="item in statusFilters"
        :key="item.key || 'all'"
        type="button"
        class="y-panel p-4 text-left transition-colors hover:border-y-line-strong hover:bg-y-surface-2"
        :class="statusFilter === item.key ? '!border-y-mint/60 bg-y-surface-2' : ''"
        :aria-pressed="statusFilter === item.key"
        @click="filterByStatus(item.key)"
      >
        <span class="y-label flex items-center gap-2">
          <span v-if="item.dot" class="y-dot" :class="item.dot" aria-hidden="true"></span>
          {{ item.label }}
        </span>
        <span class="mt-2 block font-mono text-3xl font-medium tracking-tight text-y-text">{{ item.value || 0 }}</span>
      </button>
    </section>

    <section class="y-panel overflow-hidden">
      <div class="y-panel-header">
        <label class="relative block w-full sm:max-w-md">
          <span class="sr-only">{{ $t('common.search') }}</span>
          <Search :size="16" :stroke-width="1.5" class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-y-faint" />
          <input
            v-model="searchQuery"
            type="text"
            :placeholder="$t('adminDomains.searchPlaceholder')"
            class="input input-bordered h-10 min-h-0 w-full pl-9 pr-10 text-sm"
            @input="debouncedSearch"
          />
          <button
            v-if="searchQuery"
            type="button"
            class="btn btn-ghost btn-xs btn-square absolute right-2 top-1/2 -translate-y-1/2 text-y-faint"
            :aria-label="$t('uiAdmin1.clearSearch')"
            @click="clearSearch"
          >
            <X :size="14" :stroke-width="1.5" />
          </button>
        </label>
        <div class="flex flex-wrap items-center gap-2 text-sm text-y-muted">
          <button
            v-if="statusFilter"
            type="button"
            class="y-chip-mint"
            :aria-label="$t('uiAdmin1.clearFilter')"
            @click="filterByStatus('')"
          >
            {{ $t('adminDomains.filtering') }}: {{ domainStatusLabel(statusFilter) }}
            <X :size="12" :stroke-width="1.5" />
          </button>
          <span v-if="searchQuery" class="text-xs text-y-faint">
            {{ $t('adminDomains.searchResults', { count: domains.length, query: searchQuery }) }}
          </span>
          <span v-else class="font-mono text-xs text-y-faint">{{ $t('adminDomains.totalCount', { count: pagination.total }) }}</span>
        </div>
      </div>

      <YLoader v-if="loading" :label="$t('common.loading')" />

      <EmptyState
        v-else-if="domains.length === 0"
        :title="searchQuery ? $t('adminDomains.noSearchResults') : $t('adminDomains.noData')"
      >
        <button v-if="searchQuery" type="button" class="btn btn-outline btn-sm" @click="clearSearch">
          {{ $t('uiAdmin1.clearSearch') }}
        </button>
      </EmptyState>

      <div v-else class="overflow-x-auto">
        <table class="y-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>{{ $t('adminDomains.domain') }}</th>
              <th>{{ $t('adminDomains.owner') }}</th>
              <th>{{ $t('adminDomains.rootDomain') }}</th>
              <th>{{ $t('adminDomains.status') }}</th>
              <th>{{ $t('adminDomains.registeredAt') }}</th>
              <th>{{ $t('adminDomains.expiresAt') }}</th>
              <th>{{ $t('adminDomains.autoRenew') }}</th>
              <th class="text-right">{{ $t('adminDomains.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="domain in domains" :key="domain.id">
              <td class="font-mono text-xs text-y-faint">{{ domain.id }}</td>
              <td>
                <span class="y-domain block">{{ domain.full_domain }}</span>
                <span v-if="!domain.use_default_nameservers" class="y-tag mt-1">{{ $t('adminDomains.customNS') }}</span>
              </td>
              <td>
                <div v-if="domain.user" class="min-w-0">
                  <span class="block text-sm font-medium text-y-text">{{ domain.user.username }}</span>
                  <span class="block text-xs text-y-faint">{{ domain.user.email }}</span>
                </div>
                <span v-else class="text-y-faint">—</span>
              </td>
              <td>
                <span v-if="domain.root_domain" class="font-mono text-sm text-y-muted">{{ domain.root_domain.domain }}</span>
                <span v-else class="text-y-faint">—</span>
              </td>
              <td class="whitespace-nowrap">
                <StatusDot :tone="domainStatusTone(domain.status)" :label="domainStatusLabel(domain.status)" />
              </td>
              <td class="whitespace-nowrap text-sm text-y-muted">{{ formatDate(domain.registered_at) }}</td>
              <td class="whitespace-nowrap">
                <div class="flex flex-col items-start gap-1">
                  <span class="text-sm text-y-muted" :class="getExpiryClass(domain.expires_at)">
                    {{ formatDate(domain.expires_at) }}
                  </span>
                  <span v-if="getExpiryStatus(domain.expires_at)" :class="getExpiryBadgeClass(domain.expires_at)">
                    {{ getExpiryStatus(domain.expires_at) }}
                  </span>
                </div>
              </td>
              <td>
                <span v-if="domain.auto_renew" class="inline-flex text-y-mint-text" :title="$t('common.yes')">
                  <Check :size="16" :stroke-width="1.5" />
                  <span class="sr-only">{{ $t('common.yes') }}</span>
                </span>
                <span v-else class="text-y-faint">—</span>
              </td>
              <td>
                <div class="flex justify-end gap-1">
                  <button
                    type="button"
                    class="btn btn-ghost btn-sm btn-square"
                    :title="$t('adminDomains.detailsTooltip')"
                    :aria-label="$t('adminDomains.detailsTooltip')"
                    @click="viewDomainDetails(domain)"
                  >
                    <Eye :size="16" :stroke-width="1.5" />
                  </button>
                  <button
                    type="button"
                    class="btn btn-ghost btn-sm btn-square"
                    :class="domain.status === 'suspended' ? 'text-y-mint-text' : 'text-y-warn'"
                    :title="domain.status === 'suspended' ? $t('adminDomains.activateTooltip') : $t('adminDomains.suspendTooltip')"
                    :aria-label="domain.status === 'suspended' ? $t('adminDomains.activateTooltip') : $t('adminDomains.suspendTooltip')"
                    @click="toggleDomainStatus(domain)"
                  >
                    <CirclePlay v-if="domain.status === 'suspended'" :size="16" :stroke-width="1.5" />
                    <CirclePause v-else :size="16" :stroke-width="1.5" />
                  </button>
                  <button
                    type="button"
                    class="btn btn-ghost btn-sm btn-square text-y-danger-text"
                    :title="$t('adminDomains.deleteTooltip')"
                    :aria-label="$t('adminDomains.deleteTooltip')"
                    @click="confirmDelete(domain)"
                  >
                    <Trash2 :size="16" :stroke-width="1.5" />
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div
        v-if="!loading && pagination.total_pages > 1"
        class="flex flex-col items-center justify-between gap-3 border-t border-y-line px-5 py-3 sm:flex-row"
      >
        <p class="font-mono text-xs text-y-faint">{{ $t('uiAdmin1.pageOf', { page: pagination.page, total: pagination.total_pages }) }}</p>
        <div class="join">
          <button
            type="button"
            class="join-item btn btn-ghost btn-sm btn-square"
            :disabled="pagination.page === 1"
            :aria-label="$t('common.previous')"
            @click="goToPage(pagination.page - 1)"
          >
            <ChevronLeft :size="16" :stroke-width="1.5" />
          </button>
          <template v-for="(page, index) in visiblePages" :key="index">
            <button
              v-if="typeof page === 'number'"
              type="button"
              class="join-item btn btn-ghost btn-sm min-w-[2.125rem] px-2 font-mono font-medium"
              :class="page === pagination.page ? 'bg-y-surface-2 text-y-mint-text' : 'text-y-muted'"
              :aria-current="page === pagination.page ? 'page' : undefined"
              @click="goToPage(page)"
            >
              {{ page }}
            </button>
            <span v-else class="join-item flex h-[2.125rem] items-center px-2 font-mono text-xs text-y-faint">…</span>
          </template>
          <button
            type="button"
            class="join-item btn btn-ghost btn-sm btn-square"
            :disabled="pagination.page === pagination.total_pages"
            :aria-label="$t('common.next')"
            @click="goToPage(pagination.page + 1)"
          >
            <ChevronRight :size="16" :stroke-width="1.5" />
          </button>
        </div>
      </div>
    </section>

    <!-- Domain Details Modal -->
    <dialog class="modal" :class="{ 'modal-open': showDetailsModal }">
      <div class="modal-box w-11/12 max-w-3xl">
        <h3 class="text-lg font-semibold text-y-text">{{ $t('adminDomains.domainDetails') }}</h3>
        <dl v-if="selectedDomain" class="mt-5 grid grid-cols-1 gap-x-6 gap-y-4 sm:grid-cols-2">
          <div>
            <dt class="y-label">{{ $t('adminDomains.domainId') }}</dt>
            <dd class="mt-1 font-mono text-sm text-y-text">{{ selectedDomain.id }}</dd>
          </div>
          <div>
            <dt class="y-label">{{ $t('adminDomains.fullDomain') }}</dt>
            <dd class="y-domain mt-1 text-sm">{{ selectedDomain.full_domain }}</dd>
          </div>
          <div>
            <dt class="y-label">{{ $t('adminDomains.subdomain') }}</dt>
            <dd class="mt-1 break-all font-mono text-sm text-y-text">{{ selectedDomain.subdomain }}</dd>
          </div>
          <div>
            <dt class="y-label">{{ $t('adminDomains.rootDomain') }}</dt>
            <dd class="mt-1 break-all font-mono text-sm text-y-text">{{ selectedDomain.root_domain?.domain }}</dd>
          </div>
          <div>
            <dt class="y-label">{{ $t('adminDomains.status') }}</dt>
            <dd class="mt-1">
              <StatusDot :tone="domainStatusTone(selectedDomain.status)" :label="domainStatusLabel(selectedDomain.status)" />
            </dd>
          </div>
          <div>
            <dt class="y-label">{{ $t('adminDomains.owner') }}</dt>
            <dd class="mt-1 text-sm text-y-text">
              {{ selectedDomain.user?.username }}
              <span class="break-all text-y-muted">({{ selectedDomain.user?.email }})</span>
            </dd>
          </div>
          <div>
            <dt class="y-label">{{ $t('adminDomains.registeredAt') }}</dt>
            <dd class="mt-1 text-sm text-y-text">{{ formatDate(selectedDomain.registered_at) }}</dd>
          </div>
          <div>
            <dt class="y-label">{{ $t('adminDomains.expiresAt') }}</dt>
            <dd class="mt-1 text-sm text-y-text">{{ formatDate(selectedDomain.expires_at) }}</dd>
          </div>
          <div>
            <dt class="y-label">{{ $t('adminDomains.autoRenew') }}</dt>
            <dd class="mt-1 text-sm text-y-text">{{ selectedDomain.auto_renew ? $t('common.yes') : $t('common.no') }}</dd>
          </div>
          <div>
            <dt class="y-label">{{ $t('adminDomains.dnsSynced') }}</dt>
            <dd class="mt-1">
              <StatusDot :tone="selectedDomain.dns_synced ? 'ok' : 'warn'" :label="selectedDomain.dns_synced ? $t('common.yes') : $t('common.no')" />
            </dd>
          </div>
          <div v-if="selectedDomain.nameservers" class="sm:col-span-2">
            <dt class="y-label">{{ $t('adminDomains.nameservers') }}</dt>
            <dd class="y-inset mt-1.5 break-all px-3 py-2 font-mono text-xs text-y-text">
              {{ formatNameservers(selectedDomain.nameservers) }}
            </dd>
          </div>
        </dl>
        <div class="modal-action">
          <button type="button" class="btn btn-ghost" @click="showDetailsModal = false">{{ $t('common.close') }}</button>
        </div>
      </div>
      <form method="dialog" class="modal-backdrop" @click="showDetailsModal = false">
        <button>{{ $t('common.close') }}</button>
      </form>
    </dialog>

    <!-- Delete Confirmation Modal -->
    <dialog class="modal" :class="{ 'modal-open': showDeleteModal }">
      <div class="modal-box">
        <h3 class="text-lg font-semibold text-y-text">{{ $t('adminDomains.confirmDelete') }}</h3>
        <p class="mt-3 text-sm leading-6 text-y-muted">
          {{ $t('adminDomains.confirmDeleteMessage', { domain: domainToDelete?.full_domain }) }}
        </p>
        <div class="modal-action">
          <button type="button" class="btn btn-ghost" @click="showDeleteModal = false">{{ $t('common.cancel') }}</button>
          <button type="button" class="btn btn-error" :disabled="deleting" @click="handleDelete">
            <span v-if="deleting" class="loading loading-spinner loading-sm"></span>
            <span v-else>{{ $t('common.delete') }}</span>
          </button>
        </div>
      </div>
      <form method="dialog" class="modal-backdrop" @click="showDeleteModal = false">
        <button>{{ $t('common.close') }}</button>
      </form>
    </dialog>

    <!-- Create Domain Modal -->
    <dialog class="modal" :class="{ 'modal-open': showCreateModal }">
      <div class="modal-box">
        <h3 class="text-lg font-semibold text-y-text">{{ $t('adminDomains.addDomainTitle') }}</h3>
        <div class="mt-5 space-y-4">
          <div class="y-field">
            <label class="y-field-label" for="admin-domain-user">{{ $t('adminDomains.userSearch') }}</label>
            <div class="relative">
              <input
                id="admin-domain-user"
                v-model="userSearchQuery"
                type="text"
                :placeholder="$t('adminDomains.userSearchPlaceholder')"
                class="input input-bordered w-full pr-10"
                autocomplete="off"
                @input="debouncedUserSearch"
              />
              <span v-if="userSearchLoading" class="absolute right-3 top-1/2 flex -translate-y-1/2">
                <span class="loading loading-spinner loading-sm"></span>
              </span>
              <div
                v-if="userSuggestions.length > 0"
                class="absolute z-50 mt-1 max-h-48 w-full overflow-y-auto rounded-md border border-y-line bg-y-surface py-1"
              >
                <div
                  v-for="u in userSuggestions"
                  :key="u.id"
                  class="cursor-pointer px-4 py-2 transition-colors hover:bg-y-surface-2"
                  @mousedown.prevent="selectUser(u)"
                >
                  <span class="block text-sm font-medium text-y-text">{{ u.username }}</span>
                  <span class="block text-xs text-y-faint">{{ u.email }} · ID {{ u.id }}</span>
                </div>
              </div>
            </div>
            <div v-if="createForm.selected_user" class="y-inset flex items-center gap-2 px-3 py-2">
              <UserRound :size="16" :stroke-width="1.5" class="shrink-0 text-y-mint-text" />
              <div class="min-w-0 flex-1 text-sm">
                <span class="font-medium text-y-text">{{ createForm.selected_user.username }}</span>
                <span class="ml-2 break-all text-y-muted">{{ createForm.selected_user.email }}</span>
                <span class="ml-2 font-mono text-xs text-y-faint">ID {{ createForm.selected_user.id }}</span>
              </div>
              <button
                type="button"
                class="btn btn-ghost btn-xs btn-square"
                :aria-label="$t('common.clear')"
                @click="clearSelectedUser"
              >
                <X :size="14" :stroke-width="1.5" />
              </button>
            </div>
          </div>
          <div class="y-field">
            <label class="y-field-label" for="admin-domain-subdomain">{{ $t('adminDomains.subdomainLabel') }}</label>
            <input
              id="admin-domain-subdomain"
              v-model="createForm.subdomain"
              type="text"
              :placeholder="$t('adminDomains.subdomainPlaceholder')"
              class="input input-bordered w-full font-mono"
            />
          </div>
          <div class="grid grid-cols-1 gap-4 sm:grid-cols-[1fr_8rem]">
            <div class="y-field">
              <label class="y-field-label" for="admin-domain-root">{{ $t('adminDomains.rootDomainLabel') }}</label>
              <select id="admin-domain-root" v-model="createForm.root_domain_id" class="select select-bordered w-full font-mono">
                <option value="" disabled>{{ $t('adminDomains.rootDomainSelect') }}</option>
                <option v-for="rd in rootDomains" :key="rd.id" :value="rd.id">
                  .{{ rd.domain }}
                </option>
              </select>
            </div>
            <div class="y-field">
              <label class="y-field-label" for="admin-domain-years">{{ $t('adminDomains.yearsLabel') }}</label>
              <input
                id="admin-domain-years"
                v-model.number="createForm.years"
                type="number"
                min="1"
                max="10"
                class="input input-bordered w-full font-mono"
              />
            </div>
          </div>
        </div>
        <div class="modal-action">
          <button type="button" class="btn btn-ghost" @click="closeCreateModal">{{ $t('common.cancel') }}</button>
          <button
            type="button"
            class="btn btn-primary"
            :disabled="creating || !createForm.selected_user || !createForm.subdomain || !createForm.root_domain_id"
            @click="handleCreateDomain"
          >
            <span v-if="creating" class="loading loading-spinner loading-sm"></span>
            <span v-else>{{ $t('adminDomains.addDomain') }}</span>
          </button>
        </div>
      </div>
      <form method="dialog" class="modal-backdrop" @click="closeCreateModal"><button>{{ $t('common.close') }}</button></form>
    </dialog>

    <!-- Suspend Reason Modal -->
    <dialog class="modal" :class="{ 'modal-open': showSuspendModal }">
      <div class="modal-box">
        <h3 class="text-lg font-semibold text-y-text">{{ $t('adminDomains.suspendDomain') }}</h3>
        <p class="mt-3 text-sm leading-6 text-y-muted">
          {{ $t('adminDomains.suspendDomainMessage', { domain: domainToSuspend?.full_domain }) }}
        </p>
        <div class="y-field mt-4">
          <label class="y-field-label" for="admin-domain-suspend-reason">{{ $t('adminDomains.suspendReason') }}</label>
          <textarea
            id="admin-domain-suspend-reason"
            v-model="suspendReason"
            class="textarea textarea-bordered h-24 w-full"
            :placeholder="$t('adminDomains.suspendReasonPlaceholder')"
          ></textarea>
        </div>
        <div class="modal-action">
          <button type="button" class="btn btn-ghost" @click="closeSuspendModal">{{ $t('common.cancel') }}</button>
          <button type="button" class="btn btn-error" :disabled="suspending || !suspendReason.trim()" @click="handleSuspend">
            <span v-if="suspending" class="loading loading-spinner loading-sm"></span>
            <span v-else>{{ $t('adminDomains.suspend') }}</span>
          </button>
        </div>
      </div>
      <form method="dialog" class="modal-backdrop" @click="closeSuspendModal">
        <button>{{ $t('common.close') }}</button>
      </form>
    </dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import axios from '../utils/axios'
import { useToast } from '../composables/useToast'
import {
  Plus, Search, X, Check, Eye, CirclePlay, CirclePause, Trash2, ChevronLeft, ChevronRight, UserRound,
} from 'lucide-vue-next'
import PageHeader from '../components/ui/PageHeader.vue'
import StatusDot from '../components/ui/StatusDot.vue'
import EmptyState from '../components/ui/EmptyState.vue'
import YLoader from '../components/brand/YLoader.vue'

const { t } = useI18n()
const toast = useToast()

const allDomains = ref([]) // 存储所有域名
const domains = ref([]) // 显示的域名（可能经过过滤）
const searchQuery = ref('')
const statusFilter = ref('') // 状态筛选：''=全部, 'active', 'expired', 'suspended'
const loading = ref(true)
const showDetailsModal = ref(false)
const showDeleteModal = ref(false)
const showSuspendModal = ref(false)
const showCreateModal = ref(false)
const selectedDomain = ref(null)
const domainToDelete = ref(null)
const domainToSuspend = ref(null)
const suspendReason = ref('')
const deleting = ref(false)
const suspending = ref(false)
const creating = ref(false)
const rootDomains = ref([])
const userSearchQuery = ref('')
const userSuggestions = ref([])
const userSearchLoading = ref(false)
const createForm = ref({
  selected_user: null,
  subdomain: '',
  root_domain_id: '',
  years: 1
})
let userSearchTimeout = null
const stats = ref({
  total: 0,
  active: 0,
  expired: 0,
  suspended: 0,
  abuse: 0
})
const pagination = ref({
  page: 1,
  page_size: 20,
  total: 0,
  total_pages: 0
})
let searchTimeout = null


const statusFilters = computed(() => [
  { key: '', dot: '', label: t('uiAdmin1.filters.all'), value: stats.value.total },
  { key: 'active', dot: 'bg-y-mint', label: t('uiAdmin1.filters.active'), value: stats.value.active },
  { key: 'expired', dot: 'bg-y-danger', label: t('uiAdmin1.filters.expired'), value: stats.value.expired },
  { key: 'suspended', dot: 'bg-y-warn', label: t('uiAdmin1.filters.suspended'), value: stats.value.suspended },
  { key: 'abuse', dot: 'bg-y-danger', label: t('uiAdmin1.filters.abuse'), value: stats.value.abuse },
])

const domainStatusTone = (status) => ({
  active: 'ok',
  suspended: 'warn',
  expired: 'danger',
  abuse: 'danger',
}[status] || 'muted')

const domainStatusLabel = (status) => {
  const labels = {
    active: t('uiAdmin1.status.active'),
    suspended: t('uiAdmin1.status.suspended'),
    expired: t('uiAdmin1.status.expired'),
    abuse: t('uiAdmin1.status.abuse'),
  }
  return labels[status] || status
}

const fetchStats = async () => {
  try {
    const response = await axios.get('/api/admin/domains/stats')
    stats.value = response.data
  } catch (error) {
    console.error('Failed to fetch domain stats:', error)
  }
}

const fetchDomains = async (search = '') => {
  loading.value = true
  try {
    const params = {
      page: pagination.value.page,
      page_size: pagination.value.page_size
    }
    if (search) {
      params.search = search
    }
    if (statusFilter.value) {
      params.status = statusFilter.value
    }
    const response = await axios.get('/api/admin/domains', { params })
    domains.value = response.data.domains || []
    if (response.data.pagination) {
      pagination.value = response.data.pagination
    }
    // 首次加载时也获取所有域名用于统计（只在第一页时）
    if (pagination.value.page === 1 && !search) {
      allDomains.value = domains.value
    }
  } catch (error) {
    toast.error(t('adminDomains.fetchFailed'))
  } finally {
    loading.value = false
  }
}

const debouncedSearch = () => {
  if (searchTimeout) {
    clearTimeout(searchTimeout)
  }
  searchTimeout = setTimeout(() => {
    pagination.value.page = 1
    fetchDomains(searchQuery.value)
  }, 500)
}

const clearSearch = () => {
  searchQuery.value = ''
  pagination.value.page = 1
  fetchDomains()
}

const filterByStatus = (status) => {
  statusFilter.value = status
  pagination.value.page = 1
  searchQuery.value = '' // 清空搜索
  fetchDomains()
}

const goToPage = (page) => {
  if (page >= 1 && page <= pagination.value.total_pages) {
    pagination.value.page = page
    fetchDomains(searchQuery.value)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }
}

const visiblePages = computed(() => {
  const current = pagination.value.page
  const total = pagination.value.total_pages
  const pages = []

  if (total <= 7) {
    for (let i = 1; i <= total; i++) {
      pages.push(i)
    }
  } else {
    if (current <= 4) {
      for (let i = 1; i <= 5; i++) {
        pages.push(i)
      }
      pages.push('...')
      pages.push(total)
    } else if (current >= total - 3) {
      pages.push(1)
      pages.push('...')
      for (let i = total - 4; i <= total; i++) {
        pages.push(i)
      }
    } else {
      pages.push(1)
      pages.push('...')
      for (let i = current - 1; i <= current + 1; i++) {
        pages.push(i)
      }
      pages.push('...')
      pages.push(total)
    }
  }

  return pages.filter(p => p !== '...' || pages.indexOf(p) === pages.lastIndexOf(p))
})

const viewDomainDetails = (domain) => {
  selectedDomain.value = domain
  showDetailsModal.value = true
}

const confirmDelete = (domain) => {
  domainToDelete.value = domain
  showDeleteModal.value = true
}

const handleDelete = async () => {
  deleting.value = true
  try {
    await axios.delete(`/api/admin/domains/${domainToDelete.value.id}`)
    toast.success(t('adminDomains.deleteSuccess'))
    showDeleteModal.value = false
    await fetchStats() // 刷新统计
    await fetchDomains(searchQuery.value)
  } catch (error) {
    toast.error(error.response?.data?.error || t('adminDomains.deleteFailed'))
  } finally {
    deleting.value = false
  }
}

const toggleDomainStatus = async (domain) => {
  const newStatus = domain.status === 'suspended' ? 'active' : 'suspended'
  
  // If suspending, show modal to get reason
  if (newStatus === 'suspended') {
    domainToSuspend.value = domain
    suspendReason.value = ''
    showSuspendModal.value = true
    return
  }
  
  // If activating, proceed directly
  try {
    await axios.put(`/api/admin/domains/${domain.id}/status`, { status: newStatus })
    toast.success(t('adminDomains.statusUpdateSuccess'))
    await fetchStats() // 刷新统计
    await fetchDomains(searchQuery.value)
  } catch (error) {
    toast.error(error.response?.data?.error || t('adminDomains.statusUpdateFailed'))
  }
}

const closeSuspendModal = () => {
  showSuspendModal.value = false
  domainToSuspend.value = null
  suspendReason.value = ''
}

const handleSuspend = async () => {
  if (!suspendReason.value.trim()) {
    toast.error(t('adminDomains.reasonRequired'))
    return
  }
  
  suspending.value = true
  try {
    await axios.put(`/api/admin/domains/${domainToSuspend.value.id}/status`, { 
      status: 'suspended',
      reason: suspendReason.value.trim()
    })
    toast.success(t('adminDomains.statusUpdateSuccess'))
    closeSuspendModal()
    await fetchStats() // 刷新统计
    await fetchDomains(searchQuery.value)
  } catch (error) {
    toast.error(error.response?.data?.error || t('adminDomains.statusUpdateFailed'))
  } finally {
    suspending.value = false
  }
}

const isExpiringSoon = (expiresAt) => {
  const now = new Date()
  const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000)
  const expiryDate = new Date(expiresAt)
  return expiryDate <= thirtyDaysFromNow && expiryDate > now
}

// 获取过期状态文本
const getExpiryStatus = (expiresAt) => {
  const now = new Date()
  const expiryDate = new Date(expiresAt)
  const daysUntilExpiry = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24))

  if (daysUntilExpiry > 30) {
    return null // 超过 30 天不显示状态
  } else if (daysUntilExpiry > 0 && daysUntilExpiry <= 7) {
    return t('adminDomains.expiringInDays', { days: daysUntilExpiry })
  } else if (daysUntilExpiry > 7 && daysUntilExpiry <= 30) {
    return t('adminDomains.expiringSoon')
  } else if (daysUntilExpiry <= 0 && daysUntilExpiry >= -20) {
    return t('adminDomains.expired', { days: Math.abs(daysUntilExpiry) })
  } else if (daysUntilExpiry < -20) {
    return t('adminDomains.willBeDeleted', { days: 30 - Math.abs(daysUntilExpiry) })
  }
  return null
}

// 获取过期状态样式类
const getExpiryBadgeClass = (expiresAt) => {
  const now = new Date()
  const expiryDate = new Date(expiresAt)
  const daysUntilExpiry = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24))

  if (daysUntilExpiry > 7 && daysUntilExpiry <= 30) {
    return 'y-chip-warn' // 即将过期 (7-30 天)
  } else if (daysUntilExpiry > 0 && daysUntilExpiry <= 7) {
    return 'y-chip-danger' // 即将过期 (0-7 天)
  } else if (daysUntilExpiry <= 0 && daysUntilExpiry >= -20) {
    return 'y-chip-danger' // 已过期 (0-20 天)
  } else if (daysUntilExpiry < -20) {
    return 'y-chip-danger' // 即将删除 (>20 天)
  }
  return ''
}

// 获取过期日期文本样式
const getExpiryClass = (expiresAt) => {
  const now = new Date()
  const expiryDate = new Date(expiresAt)
  const daysUntilExpiry = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24))

  if (daysUntilExpiry <= 7 && daysUntilExpiry > 0) {
    return '!text-y-danger-text font-medium' // 7 天内过期
  } else if (daysUntilExpiry <= 30 && daysUntilExpiry > 7) {
    return '!text-y-warn font-medium' // 30 天内过期
  } else if (daysUntilExpiry <= 0) {
    return '!text-y-danger-text font-medium' // 已过期
  }
  return ''
}

const formatDate = (date) => {
  return new Date(date).toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  })
}

const formatNameservers = (nameservers) => {
  try {
    const ns = JSON.parse(nameservers)
    return Array.isArray(ns) ? ns.join(', ') : nameservers
  } catch {
    return nameservers
  }
}

const fetchRootDomains = async () => {
  try {
    const response = await axios.get('/api/admin/root-domains')
    rootDomains.value = (response.data.root_domains || []).filter(rd => rd.is_active)
  } catch (error) {
    console.error('Failed to fetch root domains:', error)
  }
}

const openCreateModal = () => {
  createForm.value = { selected_user: null, subdomain: '', root_domain_id: '', years: 1 }
  userSearchQuery.value = ''
  userSuggestions.value = []
  if (rootDomains.value.length === 0) fetchRootDomains()
  showCreateModal.value = true
}

const closeCreateModal = () => {
  showCreateModal.value = false
  userSuggestions.value = []
}

const debouncedUserSearch = () => {
  if (userSearchTimeout) clearTimeout(userSearchTimeout)
  userSuggestions.value = []
  if (!userSearchQuery.value.trim()) return
  userSearchTimeout = setTimeout(async () => {
    userSearchLoading.value = true
    try {
      const res = await axios.get('/api/admin/users', {
        params: { search: userSearchQuery.value.trim(), page: 1, page_size: 8 }
      })
      userSuggestions.value = res.data.users || []
    } catch {
      userSuggestions.value = []
    } finally {
      userSearchLoading.value = false
    }
  }, 300)
}

const selectUser = (user) => {
  createForm.value.selected_user = user
  userSearchQuery.value = ''
  userSuggestions.value = []
}

const clearSelectedUser = () => {
  createForm.value.selected_user = null
}

const handleCreateDomain = async () => {
  creating.value = true
  try {
    await axios.post('/api/admin/domains', {
      user_id: createForm.value.selected_user.id,
      subdomain: createForm.value.subdomain.trim(),
      root_domain_id: createForm.value.root_domain_id,
      years: createForm.value.years || 1
    })
    toast.success(t('adminDomains.createSuccess'))
    closeCreateModal()
    await fetchStats()
    await fetchDomains(searchQuery.value)
  } catch (error) {
    toast.error(error.response?.data?.error || t('adminDomains.createFailed'))
  } finally {
    creating.value = false
  }
}

onMounted(() => {
  fetchStats()
  fetchDomains()
})
</script>
