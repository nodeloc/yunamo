<template>
  <section class="y-panel">
    <div class="y-panel-header">
      <div class="flex min-w-0 items-center gap-3">
        <span class="y-icon-tile" :class="{ '!text-y-faint': !dnssec.enabled }">
          <ShieldCheck v-if="dnssec.enabled" :size="20" :stroke-width="1.5" />
          <Shield v-else :size="20" :stroke-width="1.5" />
        </span>
        <div class="min-w-0">
          <h2 class="y-h3">DNSSEC</h2>
          <p class="mt-0.5 text-sm text-y-muted">{{ customNs ? $t('uiUser.dns.customDnssecDesc') : $t('uiUser.dns.dnssecDesc') }}</p>
        </div>
      </div>
      <div class="flex items-center gap-3">
        <StatusDot
          :tone="dnssec.enabled ? 'ok' : 'muted'"
          :label="dnssec.enabled ? $t('dnsManagement.dnssecEnabled') : $t('dnsManagement.dnssecDisabled')"
        />
        <button
          v-if="customNs"
          v-show="dnssec.enabled"
          type="button"
          class="btn btn-ghost btn-sm text-y-danger-text"
          :disabled="dnssec.loading"
          @click="removeCustomDS"
        >
          <span v-if="dnssec.loading" class="loading loading-spinner loading-xs"></span>
          <span v-else>{{ $t('uiUser.dns.customDsRemove') }}</span>
        </button>
        <button
          v-else
          type="button"
          class="btn btn-sm"
          :class="dnssec.enabled ? 'btn-ghost text-y-danger-text' : 'btn-outline'"
          :disabled="dnssec.loading"
          @click="toggleDNSSEC"
        >
          <span v-if="dnssec.loading" class="loading loading-spinner loading-xs"></span>
          <span v-else>{{ dnssec.enabled ? $t('uiUser.dns.dnssecDisable') : $t('uiUser.dns.dnssecEnable') }}</span>
        </button>
      </div>
    </div>

    <!-- Custom nameservers: the owner supplies the DS of a zone signed elsewhere -->
    <div v-if="customNs" class="space-y-4 px-5 py-5">
      <div v-if="dnssec.enabled" class="flex flex-wrap gap-2">
        <span :class="dnssec.parentSigned ? 'y-chip-mint' : 'y-chip-warn'">
          {{ dnssec.parentSigned ? $t('dnsManagement.dnssecParentSigned', { zone: dnssec.parentZone }) : $t('uiUser.dns.parentUnsigned', { zone: dnssec.parentZone }) }}
        </span>
        <span :class="dnssec.chainValid ? 'y-chip-mint' : 'y-chip'">
          {{ dnssec.chainValid ? $t('dnsManagement.dnssecChainValid') : $t('dnsManagement.dnssecChainIncomplete') }}
        </span>
      </div>

      <div v-if="dnssec.dsRecords.length > 0" class="space-y-1.5">
        <p class="y-label">{{ $t('uiUser.dns.dsRecords') }}</p>
        <div v-for="ds in dnssec.dsRecords" :key="ds" class="flex items-start gap-2">
          <code class="min-w-0 flex-1 break-all rounded-sm border border-y-line bg-y-surface px-3 py-2 text-xs text-y-text">{{ ds }}</code>
          <button type="button" class="btn btn-ghost btn-sm btn-square shrink-0" :title="$t('uiUser.common.copy')" :aria-label="$t('uiUser.common.copy')" @click="copyText(ds)">
            <Copy :size="16" :stroke-width="1.5" />
          </button>
        </div>
      </div>

      <div class="y-field">
        <label :for="`custom-ds-${domainId}`" class="y-field-label">{{ $t('uiUser.dns.customDsLabel') }}</label>
        <textarea
          :id="`custom-ds-${domainId}`"
          v-model="customDSInput"
          rows="3"
          spellcheck="false"
          :placeholder="$t('uiUser.dns.customDsPlaceholder')"
          class="textarea textarea-bordered w-full font-mono text-xs leading-5"
          :aria-describedby="`custom-ds-hint-${domainId}`"
        ></textarea>
        <p :id="`custom-ds-hint-${domainId}`" class="y-field-hint">{{ $t('uiUser.dns.customDsHint') }}</p>
      </div>
      <button type="button" class="btn btn-outline btn-sm gap-1.5" :disabled="dnssec.publishingDS" @click="publishCustomDS">
        <span v-if="dnssec.publishingDS" class="loading loading-spinner loading-xs"></span>
        <Upload v-else :size="14" :stroke-width="1.5" />
        {{ dnssec.enabled ? $t('uiUser.dns.customDsUpdate') : $t('uiUser.dns.customDsPublish') }}
      </button>
    </div>

    <div v-else-if="dnssec.enabled" class="space-y-4 px-5 py-5">
      <!-- Chain of trust status -->
      <div class="flex flex-wrap gap-2">
        <span :class="dnssec.parentSigned ? 'y-chip-mint' : 'y-chip-warn'">
          {{ dnssec.parentSigned ? $t('dnsManagement.dnssecParentSigned', { zone: dnssec.parentZone }) : $t('uiUser.dns.parentUnsigned', { zone: dnssec.parentZone }) }}
        </span>
        <span :class="dnssec.dsPublished ? 'y-chip-mint' : 'y-chip-warn'">
          {{ dnssec.dsPublished ? $t('dnsManagement.dnssecDSPublished') : $t('dnsManagement.dnssecDSMissing') }}
        </span>
        <span :class="dnssec.chainValid ? 'y-chip-mint' : 'y-chip'">
          {{ dnssec.chainValid ? $t('dnsManagement.dnssecChainValid') : $t('dnsManagement.dnssecChainIncomplete') }}
        </span>
      </div>

      <!-- Keys -->
      <div v-if="dnssec.keys.length > 0" class="space-y-3">
        <div v-for="key in dnssec.keys" :key="key.id" class="y-inset space-y-4 p-4">
          <div class="flex flex-wrap items-center gap-2">
            <span class="y-tag">{{ key.keytype.toUpperCase() }}</span>
            <span class="font-mono text-xs text-y-faint">{{ $t('uiUser.dns.algorithmBits', { algorithm: key.algorithm, bits: key.bits }) }}</span>
          </div>

          <div class="space-y-1.5">
            <p class="y-label">DNSKEY</p>
            <div class="flex items-start gap-2">
              <code class="min-w-0 flex-1 break-all rounded-sm border border-y-line bg-y-surface px-3 py-2 text-xs text-y-text">{{ key.dnskey }}</code>
              <button type="button" class="btn btn-ghost btn-sm btn-square shrink-0" :title="$t('uiUser.common.copy')" :aria-label="$t('uiUser.common.copy')" @click="copyText(key.dnskey)">
                <Copy :size="16" :stroke-width="1.5" />
              </button>
            </div>
          </div>

          <div v-if="key.ds && key.ds.length > 0" class="space-y-1.5">
            <p class="y-label">{{ $t('uiUser.dns.dsRecords') }}</p>
            <div v-for="(ds, idx) in key.ds" :key="idx" class="flex items-start gap-2">
              <code class="min-w-0 flex-1 break-all rounded-sm border border-y-line bg-y-surface px-3 py-2 text-xs text-y-text">{{ ds }}</code>
              <button type="button" class="btn btn-ghost btn-sm btn-square shrink-0" :title="$t('uiUser.common.copy')" :aria-label="$t('uiUser.common.copy')" @click="copyText(ds)">
                <Copy :size="16" :stroke-width="1.5" />
              </button>
            </div>
            <button type="button" class="btn btn-outline btn-sm mt-2 gap-1.5" :disabled="dnssec.publishingDS" @click="publishDS">
              <span v-if="dnssec.publishingDS" class="loading loading-spinner loading-xs"></span>
              <Upload v-else :size="14" :stroke-width="1.5" />
              {{ dnssec.dsPublished ? $t('uiUser.dns.republishDS') : $t('uiUser.dns.publishDS') }}
            </button>
          </div>
        </div>
      </div>

      <p v-else-if="!dnssec.loading" class="text-sm text-y-muted">{{ $t('dnsManagement.dnssecNoKeys') }}</p>
    </div>
  </section>
</template>

<script setup>
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Shield, ShieldCheck, Copy, Upload } from 'lucide-vue-next'
import axios from '../../utils/axios'
import { useToast } from '../../composables/useToast'
import StatusDot from '../ui/StatusDot.vue'

const props = defineProps({
  domainId: { type: [Number, String], required: true },
  customNs: { type: Boolean, default: false },
})

const { t } = useI18n()
const toast = useToast()

const dnssec = ref({
  enabled: false,
  keys: [],
  parentZone: '',
  parentSigned: false,
  dsPublished: false,
  chainValid: false,
  dsRecords: [],
  loading: false,
  publishingDS: false,
})

const applyDNSSECStatus = (data) => {
  dnssec.value.enabled = !!data.enabled
  dnssec.value.keys = data.keys || []
  dnssec.value.parentZone = data.parent_zone || dnssec.value.parentZone
  dnssec.value.parentSigned = !!data.parent_signed
  dnssec.value.dsPublished = !!data.ds_published
  dnssec.value.chainValid = !!data.chain_valid
  dnssec.value.dsRecords = data.ds_records || []
}

const customDSInput = ref('')

const fetchDNSSEC = async () => {
  const id = props.domainId
  try {
    const response = await axios.get(`/api/domains/${id}/dnssec`)
    if (String(props.domainId) !== String(id)) return
    applyDNSSECStatus(response.data)
  } catch (error) {
    console.error('Failed to fetch DNSSEC status:', error)
  }
}

watch(
  () => [props.domainId, props.customNs],
  () => {
    customDSInput.value = ''
    fetchDNSSEC()
  },
  { immediate: true },
)

const toggleDNSSEC = async () => {
  dnssec.value.loading = true
  try {
    if (dnssec.value.enabled) {
      if (!confirm(t('dnsManagement.disableDNSSECConfirm'))) {
        dnssec.value.loading = false
        return
      }
      const response = await axios.post(`/api/domains/${props.domainId}/dnssec/disable`)
      applyDNSSECStatus(response.data)
      toast.success(t('dnsManagement.dnssecDisabledSuccess'))
    } else {
      const response = await axios.post(`/api/domains/${props.domainId}/dnssec/enable`)
      applyDNSSECStatus(response.data)
      toast.success(t('dnsManagement.dnssecEnabledSuccess'))
      if (response.data.warning) {
        toast.warning(response.data.warning, 6000)
      }
    }
  } catch (error) {
    toast.error(error.response?.data?.error || t('dnsManagement.dnssecOperationFailed'))
  } finally {
    dnssec.value.loading = false
  }
}

const copyText = async (text) => {
  try {
    await navigator.clipboard.writeText(text)
    toast.success(t('dnsManagement.copied'))
  } catch {
    toast.error(t('dnsManagement.copyFailed'))
  }
}

const publishDS = async () => {
  dnssec.value.publishingDS = true
  try {
    const response = await axios.post(`/api/domains/${props.domainId}/dnssec/publish-ds`)
    applyDNSSECStatus(response.data)
    toast.success(response.data.message || t('dnsManagement.publishDSSuccess'))
  } catch (error) {
    toast.error(error.response?.data?.error || t('dnsManagement.publishDSFailed'))
  } finally {
    dnssec.value.publishingDS = false
  }
}

const publishCustomDS = async () => {
  const records = customDSInput.value.split('\n').map((line) => line.trim()).filter(Boolean)
  if (records.length === 0) {
    toast.error(t('uiUser.dns.customDsEmpty'))
    return
  }
  dnssec.value.publishingDS = true
  try {
    const response = await axios.post(`/api/domains/${props.domainId}/dnssec/publish-ds`, { ds_records: records })
    applyDNSSECStatus(response.data)
    customDSInput.value = ''
    toast.success(response.data.message || t('dnsManagement.publishDSSuccess'))
    if (response.data.warning) {
      toast.warning(response.data.warning, 6000)
    }
  } catch (error) {
    toast.error(error.response?.data?.error || t('dnsManagement.publishDSFailed'))
  } finally {
    dnssec.value.publishingDS = false
  }
}

const removeCustomDS = async () => {
  if (!confirm(t('uiUser.dns.customDsRemoveConfirm'))) return
  dnssec.value.loading = true
  try {
    await axios.post(`/api/domains/${props.domainId}/dnssec/disable`)
    await fetchDNSSEC()
    toast.success(t('uiUser.dns.customDsRemoved'))
  } catch (error) {
    toast.error(error.response?.data?.error || t('dnsManagement.dnssecOperationFailed'))
  } finally {
    dnssec.value.loading = false
  }
}
</script>
