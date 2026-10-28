<template>
  <section class="y-panel overflow-hidden">
    <div class="flex flex-wrap items-center justify-between gap-3 border-b border-y-line px-5 py-4 sm:px-6">
      <h2 class="text-lg font-semibold leading-[26px] text-y-text">{{ $t('app2.records.title') }}</h2>
      <div class="flex items-center gap-1">
        <span v-if="!loading" class="mr-1 font-mono text-xs text-y-faint">{{ $t('uiUser.dns.recordCount', records.length) }}</span>
        <button
          type="button"
          class="btn btn-ghost btn-xs btn-square text-y-faint hover:text-y-text"
          :disabled="syncing"
          :title="$t('uiUser.dns.sync')"
          :aria-label="$t('uiUser.dns.sync')"
          @click="syncFromPowerDNS"
        >
          <span v-if="syncing" class="loading loading-spinner loading-xs"></span>
          <RefreshCw v-else :size="14" :stroke-width="1.5" />
        </button>
      </div>
    </div>

    <YLoader v-if="loading" :size="28" :label="$t('uiUser.common.loading')" />

    <template v-else>
      <p v-if="records.length === 0" class="px-6 py-10 text-center text-sm text-y-faint">{{ $t('app2.records.empty') }}</p>

      <template v-else>
        <!-- Table, xl and up (below that the sidebar leaves too little room) -->
        <div class="hidden overflow-x-auto xl:block">
          <table class="y-table whitespace-nowrap">
            <thead>
              <tr>
                <th class="!pl-6">{{ $t('app2.records.colType') }}</th>
                <th>{{ $t('app2.records.colName') }}</th>
                <th>{{ $t('app2.records.colValue') }}</th>
                <th>{{ $t('app2.records.colTtl') }}</th>
                <th class="!pr-6"><span class="sr-only">{{ $t('app2.records.colActions') }}</span></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="record in records" :key="record.id">
                <td class="!py-2.5 !pl-6"><span :class="tagClass">{{ record.type }}</span></td>
                <td>
                  <div class="flex items-center gap-2">
                    <span
                      class="block max-w-[16rem] truncate font-mono text-[14px]"
                      :class="{ 'text-y-faint': !record.is_active }"
                      :title="record.name"
                    >{{ record.name }}</span>
                    <span v-if="!record.is_active" class="y-chip shrink-0 !py-0 text-[11px]">{{ $t('dnsManagement.inactive') }}</span>
                    <span v-if="!record.synced_to_powerdns" class="y-chip-warn shrink-0 !py-0 text-[11px]">{{ $t('app2.records.pending') }}</span>
                  </div>
                </td>
                <!-- max-w-0 + w-full: the value column takes whatever width is left and truncates, so the actions never get pushed off-screen -->
                <td class="w-full max-w-0 font-mono text-[14px] text-y-muted">
                  <span class="block truncate" :title="record.content">
                    <span v-if="record.priority != null && hasPriority(record.type)" class="me-1 text-y-faint">{{ record.priority }}</span>{{ record.content }}
                  </span>
                </td>
                <td class="text-y-faint">{{ formatTtl(record.ttl) }}</td>
                <td class="!py-1 !pr-4">
                  <div class="flex items-center justify-end gap-1">
                    <button
                      v-if="record.sync_error"
                      type="button"
                      class="btn btn-ghost btn-sm btn-square text-y-danger-text"
                      :title="$t('uiUser.dns.viewError')"
                      :aria-label="$t('uiUser.dns.viewError')"
                      @click="showErrorDetails(record.sync_error)"
                    >
                      <AlertTriangle :size="16" :stroke-width="1.5" />
                    </button>
                    <button
                      type="button"
                      class="btn btn-ghost btn-square h-11 min-h-11 w-11 text-y-faint hover:text-y-text"
                      :title="$t('uiUser.dns.edit')"
                      :aria-label="$t('app2.records.editLabel', { type: record.type, name: record.name })"
                      @click="editRecord(record)"
                    >
                      <Pencil :size="16" :stroke-width="1.5" />
                    </button>
                    <button
                      type="button"
                      class="btn btn-ghost btn-square h-11 min-h-11 w-11 text-y-faint hover:bg-y-danger/10 hover:text-y-danger-text"
                      :title="$t('uiUser.dns.delete')"
                      :aria-label="$t('app2.records.deleteLabel', { type: record.type, name: record.name })"
                      @click="confirmDelete(record)"
                    >
                      <Trash2 :size="17" :stroke-width="1.5" />
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Stacked rows, below xl -->
        <ul class="divide-y divide-y-line xl:hidden">
          <li v-for="record in records" :key="record.id" class="space-y-2 px-5 py-3.5">
            <div class="flex items-center justify-between gap-3">
              <div class="flex min-w-0 items-center gap-2.5">
                <span :class="tagClass">{{ record.type }}</span>
                <span class="truncate font-mono text-[14px]" :class="record.is_active ? 'text-y-text' : 'text-y-faint'">{{ record.name }}</span>
              </div>
              <div class="-mr-2 flex shrink-0">
                <button
                  type="button"
                  class="btn btn-ghost btn-square h-11 min-h-11 w-11 text-y-faint"
                  :aria-label="$t('app2.records.editLabel', { type: record.type, name: record.name })"
                  @click="editRecord(record)"
                >
                  <Pencil :size="16" :stroke-width="1.5" />
                </button>
                <button
                  type="button"
                  class="btn btn-ghost btn-square h-11 min-h-11 w-11 text-y-faint hover:text-y-danger-text"
                  :aria-label="$t('app2.records.deleteLabel', { type: record.type, name: record.name })"
                  @click="confirmDelete(record)"
                >
                  <Trash2 :size="17" :stroke-width="1.5" />
                </button>
              </div>
            </div>
            <p class="break-all font-mono text-[13px] text-y-muted">
              <span v-if="record.priority != null && hasPriority(record.type)" class="me-1 text-y-faint">{{ record.priority }}</span>{{ record.content }}
            </p>
            <div class="flex flex-wrap items-center gap-x-3 gap-y-1.5 text-xs text-y-faint">
              <span>{{ $t('app2.records.ttl') }} {{ formatTtl(record.ttl) }}</span>
              <span v-if="!record.is_active" class="y-chip !py-0 text-[11px]">{{ $t('dnsManagement.inactive') }}</span>
              <span v-if="!record.synced_to_powerdns" class="y-chip-warn !py-0 text-[11px]">{{ $t('app2.records.pending') }}</span>
              <button v-if="record.sync_error" type="button" class="inline-flex items-center gap-1 text-y-danger-text" @click="showErrorDetails(record.sync_error)">
                <AlertTriangle :size="14" :stroke-width="1.5" />
                {{ $t('uiUser.dns.viewError') }}
              </button>
            </div>
          </li>
        </ul>
      </template>
    </template>

    <!-- Inline add form -->
    <form
      class="flex flex-wrap items-end gap-3 border-t border-y-line bg-y-bg/40 px-5 py-[18px] sm:px-6"
      :aria-label="$t('app2.records.addLabel')"
      novalidate
      @submit.prevent="addRecord"
    >
      <label class="flex flex-[0_1_7.5rem] flex-col gap-1.5 text-[13px] text-y-muted">
        {{ $t('app2.records.type') }}
        <select v-model="addForm.type" class="select select-bordered w-full min-w-[6.5rem] font-mono text-sm">
          <option v-for="rt in RECORD_TYPES" :key="rt" :value="rt">{{ rt }}</option>
        </select>
      </label>
      <label class="flex flex-[1_1_8.75rem] flex-col gap-1.5 text-[13px] text-y-muted">
        {{ $t('app2.records.name') }}
        <input
          v-model="addForm.name"
          type="text"
          placeholder="@"
          class="input input-bordered w-full font-mono text-sm"
          autocomplete="off"
          autocapitalize="off"
          spellcheck="false"
        />
      </label>
      <label v-if="hasPriority(addForm.type)" class="flex flex-[0_1_5.5rem] flex-col gap-1.5 text-[13px] text-y-muted">
        {{ $t('app2.records.priority') }}
        <input v-model.number="addForm.priority" type="number" min="0" placeholder="10" class="input input-bordered w-full font-mono text-sm" />
      </label>
      <label class="flex flex-[3_1_15rem] flex-col gap-1.5 text-[13px] text-y-muted">
        {{ $t('app2.records.value') }}
        <input
          ref="valueInput"
          v-model="addForm.content"
          type="text"
          :placeholder="valuePlaceholder"
          class="input input-bordered w-full font-mono text-sm"
          :class="{ '!border-y-danger': addError }"
          :aria-invalid="addError ? 'true' : 'false'"
          autocomplete="off"
          autocapitalize="off"
          spellcheck="false"
          @input="addError = ''"
        />
      </label>
      <label class="flex flex-[0_1_7rem] flex-col gap-1.5 text-[13px] text-y-muted">
        {{ $t('app2.records.ttl') }}
        <select v-model.number="addForm.ttl" class="select select-bordered w-full min-w-[6rem] text-sm">
          <option v-for="opt in TTL_OPTIONS" :key="opt" :value="opt">{{ formatTtl(opt) }}</option>
        </select>
      </label>
      <button type="submit" class="btn btn-primary px-5" :disabled="adding">
        <span v-if="adding" class="loading loading-spinner loading-sm"></span>
        {{ $t('app2.records.add') }}
      </button>

      <p v-if="addError" class="basis-full text-xs text-y-danger-text" role="alert">{{ addError }}</p>
      <div v-if="addForm.type === 'ALIAS'" class="flex basis-full items-start gap-2 text-xs leading-5 text-y-muted">
        <Info :size="14" :stroke-width="1.5" class="mt-0.5 shrink-0 text-y-info" />
        <p><span class="font-medium text-y-text">{{ $t('dnsManagement.aliasHintTitle') }}</span> {{ $t('dnsManagement.aliasHint') }}</p>
      </div>
      <div v-if="addForm.type === 'CNAME' && (addForm.name.trim() === '@' || addForm.name.trim() === '')" class="flex basis-full items-start gap-2 text-xs leading-5 text-y-muted">
        <Info :size="14" :stroke-width="1.5" class="mt-0.5 shrink-0 text-y-mint-text" />
        <p><span class="font-medium text-y-text">{{ $t('dnsManagement.cnameFlatteningTitle') }}</span> {{ $t('dnsManagement.cnameFlatteningHint') }}</p>
      </div>
    </form>

    <!-- Edit modal -->
    <dialog class="modal" :class="{ 'modal-open': showEditModal }">
      <div class="modal-box w-11/12 max-w-2xl">
        <h3 class="text-lg font-semibold text-y-text">{{ $t('uiUser.dns.editTitle') }}</h3>
        <p class="mt-1 text-sm text-y-muted">{{ $t('uiUser.dns.formDesc') }}</p>

        <form class="mt-6 space-y-5" @submit.prevent="handleSubmit">
          <div class="grid gap-5 sm:grid-cols-2">
            <label class="y-field">
              <span class="y-field-label">{{ $t('dnsManagement.name') }}</span>
              <input
                v-model="form.name"
                type="text"
                :placeholder="$t('dnsManagement.namePlaceholder')"
                class="input input-bordered w-full font-mono"
                autocomplete="off"
                autocapitalize="off"
                spellcheck="false"
                required
              />
              <span class="y-field-hint">{{ $t('uiUser.dns.nameHint') }}</span>
            </label>

            <label class="y-field">
              <span class="y-field-label">{{ $t('dnsManagement.type') }}</span>
              <select v-model="form.type" class="select select-bordered w-full font-mono" required>
                <option v-for="rt in RECORD_TYPES" :key="rt" :value="rt">{{ rt }}</option>
              </select>
            </label>
          </div>

          <div v-if="form.type === 'ALIAS'" class="y-inset flex items-start gap-3 px-4 py-3 text-sm">
            <Info :size="16" :stroke-width="1.5" class="mt-0.5 shrink-0 text-y-info" />
            <p class="text-y-muted"><span class="font-medium text-y-text">{{ $t('dnsManagement.aliasHintTitle') }}</span> {{ $t('dnsManagement.aliasHint') }}</p>
          </div>
          <div v-if="form.type === 'CNAME' && (form.name === '@' || form.name === '')" class="y-mint-soft flex items-start gap-3 rounded-lg border px-4 py-3 text-sm">
            <Info :size="16" :stroke-width="1.5" class="mt-0.5 shrink-0 text-y-mint-text" />
            <p class="text-y-muted"><span class="font-medium text-y-text">{{ $t('dnsManagement.cnameFlatteningTitle') }}</span> {{ $t('dnsManagement.cnameFlatteningHint') }}</p>
          </div>

          <label class="y-field">
            <span class="y-field-label">{{ $t('dnsManagement.content') }}</span>
            <textarea
              v-model="form.content"
              class="textarea textarea-bordered w-full font-mono text-sm"
              rows="3"
              :placeholder="$t('dnsManagement.contentPlaceholder')"
              spellcheck="false"
              required
            ></textarea>
          </label>

          <div class="grid gap-5 sm:grid-cols-2">
            <label class="y-field">
              <span class="y-field-label">{{ $t('uiUser.dns.ttlLabel') }}</span>
              <input v-model.number="form.ttl" type="number" min="60" max="86400" class="input input-bordered w-full font-mono" required />
              <span class="y-field-hint">{{ $t('uiUser.dns.ttlHint') }}</span>
            </label>

            <label v-if="hasPriority(form.type)" class="y-field">
              <span class="y-field-label">{{ $t('dnsManagement.priority') }}</span>
              <input v-model.number="form.priority" type="number" min="0" class="input input-bordered w-full font-mono" />
            </label>
          </div>

          <label class="y-inset flex cursor-pointer items-center justify-between gap-4 px-4 py-3">
            <span>
              <span class="block text-sm font-medium text-y-text">{{ $t('uiUser.dns.active') }}</span>
              <span class="block text-xs text-y-faint">{{ $t('uiUser.dns.activeHint') }}</span>
            </span>
            <input v-model="form.is_active" type="checkbox" class="toggle toggle-sm" />
          </label>

          <div class="modal-action">
            <button type="button" class="btn btn-ghost" @click="closeModal">{{ $t('common.cancel') }}</button>
            <button type="submit" class="btn btn-primary" :disabled="submitting">
              <span v-if="submitting" class="loading loading-spinner loading-sm"></span>
              <span v-else>{{ $t('uiUser.dns.save') }}</span>
            </button>
          </div>
        </form>
      </div>
      <form method="dialog" class="modal-backdrop" @click="closeModal">
        <button>close</button>
      </form>
    </dialog>

    <!-- Sync error modal -->
    <dialog class="modal" :class="{ 'modal-open': showErrorModal }">
      <div class="modal-box">
        <h3 class="flex items-center gap-2 text-lg font-semibold text-y-text">
          <AlertTriangle :size="18" :stroke-width="1.5" class="text-y-danger-text" />
          {{ $t('uiUser.dns.syncErrorTitle') }}
        </h3>
        <p class="mt-1 text-sm text-y-muted">{{ $t('uiUser.dns.syncErrorDesc') }}</p>

        <div class="y-inset mt-5 max-h-72 overflow-auto p-4">
          <pre class="whitespace-pre-wrap break-words font-mono text-xs text-y-text">{{ currentError }}</pre>
        </div>

        <div class="modal-action">
          <button type="button" class="btn btn-ghost" @click="closeErrorModal">{{ $t('common.close') }}</button>
          <button type="button" class="btn btn-outline gap-1.5" @click="copyError">
            <Check v-if="errorCopied" :size="16" :stroke-width="1.5" class="text-y-mint-text" />
            <Copy v-else :size="16" :stroke-width="1.5" />
            {{ errorCopied ? $t('uiUser.common.copied') : $t('uiUser.dns.copyError') }}
          </button>
        </div>
      </div>
      <form method="dialog" class="modal-backdrop" @click="closeErrorModal">
        <button>close</button>
      </form>
    </dialog>
  </section>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { RefreshCw, Pencil, Trash2, AlertTriangle, Info, Copy, Check } from 'lucide-vue-next'
import axios from '../../utils/axios'
import { useToast } from '../../composables/useToast'
import YLoader from '../brand/YLoader.vue'

const props = defineProps({
  domainId: { type: [Number, String], required: true },
})
const emit = defineEmits(['count'])

const { t } = useI18n()
const toast = useToast()

const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'ALIAS', 'MX', 'TXT', 'NS', 'SRV', 'CAA']
const TTL_OPTIONS = [60, 300, 1800, 3600, 14400, 86400]
const VALUE_PLACEHOLDERS = {
  A: '203.0.113.10',
  AAAA: '2001:db8::1',
  CNAME: 'web.example.net',
  ALIAS: 'app.example.net',
  MX: 'mail.example.com',
  TXT: '"verify=abc123"',
  NS: 'ns1.example.com',
  SRV: '5 5060 sip.example.com',
  CAA: '0 issue "letsencrypt.org"',
}

const tagClass =
  'inline-flex items-center rounded-[6px] border border-y-mint/25 bg-y-mint/10 px-2 py-[3px] font-mono text-xs font-medium leading-4 text-y-mint-text'

const hasPriority = (type) => type === 'MX' || type === 'SRV'

const records = ref([])
const loading = ref(true)
const syncing = ref(false)
const submitting = ref(false)
const showEditModal = ref(false)
const showErrorModal = ref(false)
const editingRecord = ref(null)
const currentError = ref('')
const errorCopied = ref(false)

const emptyAddForm = (type = 'CNAME') => ({ type, name: '', content: '', ttl: 3600, priority: null })
const addForm = ref(emptyAddForm())
const adding = ref(false)
const addError = ref('')
const valueInput = ref(null)
const valuePlaceholder = computed(() => VALUE_PLACEHOLDERS[addForm.value.type] || '')

const form = ref({
  name: '@',
  type: 'A',
  content: '',
  ttl: 3600,
  priority: null,
  is_active: true,
})

// Selection can change while a request is in flight; only the newest response may land.
let requestSeq = 0

const fetchRecords = async () => {
  const seq = ++requestSeq
  const id = props.domainId
  try {
    const response = await axios.get(`/api/dns/${id}/records`)
    if (seq !== requestSeq) return
    records.value = response.data.records || []
    emit('count', records.value.length)
  } catch (error) {
    if (seq === requestSeq) console.error('Failed to fetch DNS records:', error)
  } finally {
    if (seq === requestSeq) loading.value = false
  }
}

watch(
  () => props.domainId,
  () => {
    records.value = []
    loading.value = true
    addForm.value = emptyAddForm(addForm.value.type)
    addError.value = ''
    closeModal()
    closeErrorModal()
    fetchRecords()
  },
  { immediate: true }
)

const formatTtl = (ttl) => {
  const n = Number(ttl)
  if (!n) return '—'
  if (n % 86400 === 0) return t('app2.records.ttlDay', n / 86400)
  if (n % 3600 === 0) return t('app2.records.ttlHr', { n: n / 3600 })
  if (n % 60 === 0) return t('app2.records.ttlMin', { n: n / 60 })
  return t('app2.records.ttlSec', { n })
}

const addRecord = async () => {
  const content = addForm.value.content.trim()
  if (!content) {
    addError.value = t('app2.records.valueRequired')
    valueInput.value?.focus()
    return
  }
  adding.value = true
  try {
    await axios.post(`/api/dns/${props.domainId}/records`, {
      name: addForm.value.name.trim() || '@',
      type: addForm.value.type,
      content,
      ttl: addForm.value.ttl,
      priority: hasPriority(addForm.value.type) && addForm.value.priority !== '' ? addForm.value.priority : null,
      is_active: true,
    })
    toast.success(t('dnsManagement.recordAdded'))
    addForm.value = emptyAddForm(addForm.value.type)
    await fetchRecords()
  } catch (error) {
    toast.error(error.response?.data?.error || t('dnsManagement.operationFailed'))
  } finally {
    adding.value = false
  }
}

const handleSubmit = async () => {
  submitting.value = true
  try {
    await axios.put(`/api/dns/${props.domainId}/records/${editingRecord.value.id}`, form.value)
    toast.success(t('dnsManagement.recordUpdated'))
    closeModal()
    await fetchRecords()
  } catch (error) {
    toast.error(error.response?.data?.error || t('dnsManagement.operationFailed'))
  } finally {
    submitting.value = false
  }
}

const editRecord = (record) => {
  editingRecord.value = record
  form.value = {
    name: record.name,
    type: record.type,
    content: record.content,
    ttl: record.ttl,
    priority: record.priority,
    is_active: record.is_active,
  }
  showEditModal.value = true
}

const confirmDelete = async (record) => {
  if (confirm(t('dnsManagement.deleteConfirm'))) {
    try {
      await axios.delete(`/api/dns/${props.domainId}/records/${record.id}`)
      toast.success(t('dnsManagement.recordDeleted'))
      await fetchRecords()
    } catch (error) {
      toast.error(error.response?.data?.error || t('dnsManagement.operationFailed'))
    }
  }
}

function closeModal() {
  showEditModal.value = false
  editingRecord.value = null
  form.value = {
    name: '@',
    type: 'A',
    content: '',
    ttl: 3600,
    priority: null,
    is_active: true,
  }
}

const syncFromPowerDNS = async () => {
  if (!confirm(t('dnsManagement.syncConfirm'))) {
    return
  }

  syncing.value = true
  try {
    const response = await axios.post(`/api/dns/${props.domainId}/records/sync-from-powerdns`)
    const stats = response.data.stats
    toast.success(
      t('dnsManagement.syncSuccess', {
        created: stats.created,
        updated: stats.updated,
        skipped: stats.skipped,
      })
    )
    await fetchRecords()
  } catch (error) {
    toast.error(error.response?.data?.error || t('dnsManagement.syncFailed'))
  } finally {
    syncing.value = false
  }
}

const showErrorDetails = (error) => {
  currentError.value = error
  errorCopied.value = false
  showErrorModal.value = true
}

function closeErrorModal() {
  showErrorModal.value = false
  currentError.value = ''
  errorCopied.value = false
}

const copyError = async () => {
  try {
    await navigator.clipboard.writeText(currentError.value)
    errorCopied.value = true
    setTimeout(() => {
      errorCopied.value = false
    }, 2000)
  } catch (error) {
    console.error('Failed to copy error:', error)
    toast.error(t('dnsManagement.copyFailed'))
  }
}
</script>
