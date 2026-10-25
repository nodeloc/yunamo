<template>
  <div>
    <div class="y-page-wide">
      <YLoader v-if="loading" :label="$t('uiDomains.loading')" />

      <!-- Empty -->
      <section v-else-if="domains.length === 0" class="y-panel">
        <EmptyState :title="$t('app2.domains.emptyDetailTitle')" :description="$t('app2.domains.emptyDetailDesc')">
          <router-link to="/" class="btn btn-primary gap-1.5">
            <Plus :size="16" :stroke-width="1.5" />
            {{ $t('app2.domains.newSubdomain') }}
          </router-link>
        </EmptyState>
      </section>

      <main v-else class="flex flex-col gap-8 lg:flex-row lg:items-start">
        <!-- Left: domain list, usage, new -->
        <aside class="flex w-full flex-col gap-4 lg:w-80 lg:shrink-0">
          <h1 class="text-[26px] font-semibold leading-8 tracking-[-0.03em] text-y-text">{{ $t('app2.domains.title') }}</h1>

          <!-- Search + status filter -->
          <div class="flex flex-col gap-2">
            <label class="input input-bordered input-sm flex w-full items-center gap-2">
              <Search :size="14" :stroke-width="1.5" class="shrink-0 text-y-faint" />
              <input
                v-model="searchQuery"
                type="search"
                class="min-w-0 grow bg-transparent font-mono text-[13px]"
                :placeholder="$t('uiDomains.searchPlaceholder')"
                :aria-label="$t('uiDomains.searchLabel')"
                autocomplete="off"
                autocapitalize="off"
                spellcheck="false"
              />
            </label>
            <div role="tablist" class="tabs tabs-boxed tabs-sm w-full" :aria-label="$t('uiDomains.filterLabel')">
              <button
                v-for="opt in filterOptions"
                :key="opt.key"
                type="button"
                role="tab"
                class="tab flex-1 gap-1"
                :class="{ 'tab-active': statusFilter === opt.key }"
                :aria-selected="statusFilter === opt.key"
                @click="statusFilter = opt.key"
              >
                {{ opt.label }}
                <span class="font-mono text-[11px] text-y-faint">{{ opt.count }}</span>
              </button>
            </div>
          </div>

          <!-- Domain list -->
          <div class="y-panel flex flex-col gap-0.5 p-1.5" role="list" :aria-label="$t('app2.domains.listLabel')">
            <div v-if="rows.length === 0" class="px-4 py-8 text-center">
              <p class="text-sm text-y-muted">{{ $t('uiDomains.noMatchTitle') }}</p>
              <button type="button" class="btn btn-ghost btn-sm mt-2" @click="clearFilters">{{ $t('uiDomains.clearFilters') }}</button>
            </div>
            <button
              v-for="row in rows"
              :key="row.domain.id"
              type="button"
              role="listitem"
              class="flex min-h-11 w-full items-center gap-2.5 rounded-md px-3 py-2 text-left transition-colors hover:bg-y-surface-2"
              :class="{ 'bg-y-surface-2': activeDomain && row.domain.id === activeDomain.id }"
              :aria-pressed="activeDomain && row.domain.id === activeDomain.id ? 'true' : 'false'"
              @click="selectDomain(row.domain)"
            >
              <span
                aria-hidden="true"
                class="h-[7px] w-[7px] shrink-0 rounded-full"
                :class="dotActive(row.domain) ? 'y-dot-live' : 'bg-y-faint'"
              ></span>
              <span class="min-w-0 flex-1 truncate font-mono text-[13px] leading-5" :class="isRestricted(row.domain) ? 'text-y-muted' : 'text-y-text'">
                {{ row.domain.full_domain }}
              </span>
              <span class="whitespace-nowrap text-xs" :class="row.domain.status === 'active' ? 'text-y-faint' : statusTextClass(row.domain.status)">
                {{ listStatus(row.domain) }}
              </span>
            </button>
          </div>

          <!-- Usage -->
          <div class="y-panel flex flex-col gap-2.5 p-4">
            <div class="flex items-baseline justify-between text-[13px] text-y-muted">
              <span>{{ $t('app2.domains.usage') }}</span>
              <span class="font-mono text-y-text">
                {{ domains.length }}<span v-if="domainQuota !== null" class="text-y-faint"> / {{ domainQuota }}</span>
              </span>
            </div>
            <div
              v-if="quotaPercent !== null"
              class="h-1.5 overflow-hidden rounded-full bg-y-surface-2"
              role="img"
              :aria-label="$t('app2.domains.usageAria', { used: domains.length, quota: domainQuota })"
            >
              <div class="h-full rounded-full bg-y-mint transition-[width] duration-300" :style="{ width: quotaPercent + '%' }"></div>
            </div>
            <p v-if="slotsLeft !== null && slotsLeft === 0" class="text-xs leading-5 text-y-warn">{{ $t('app2.domains.quotaFull') }}</p>
            <p v-if="expiringCount > 0" class="text-xs text-y-faint">{{ $t('app2.domains.expiringCount', { n: expiringCount }) }}</p>
            <p v-if="attentionCount > 0" class="text-xs text-y-faint">{{ $t('app2.domains.attentionCount', attentionCount) }}</p>
          </div>

          <router-link to="/" class="btn btn-primary w-full gap-1.5">
            <Plus :size="16" :stroke-width="1.5" />
            {{ $t('app2.domains.newSubdomain') }}
          </router-link>

          <button v-if="fossbillingEnabled" type="button" class="btn btn-outline btn-sm w-full gap-1.5" @click="openSyncModal">
            <ArrowLeftRight :size="14" :stroke-width="1.5" />
            {{ $t('uiDomains.syncTitle') }}
          </button>
        </aside>

        <!-- Right: selected domain -->
        <section v-if="activeDomain" class="flex min-w-0 flex-1 flex-col gap-5">
          <!-- Header -->
          <div class="flex flex-wrap items-end gap-4 sm:gap-6">
            <div class="flex min-w-0 flex-[1_1_20rem] flex-col gap-1.5">
              <div class="flex items-center gap-2.5">
                <span class="y-domain break-anywhere text-2xl leading-8 tracking-[-0.02em]">{{ activeDomain.full_domain }}</span>
                <a
                  :href="'https://' + activeDomain.full_domain"
                  target="_blank"
                  rel="noopener"
                  class="inline-flex shrink-0 text-y-faint transition-colors hover:text-y-text"
                  :aria-label="$t('app2.domains.openSite', { domain: activeDomain.full_domain })"
                >
                  <SquareArrowOutUpRight :size="18" :stroke-width="1.5" />
                </a>
              </div>
              <p class="text-[13px] text-y-faint">
                {{ $t('app2.domains.claimed', { date: formatDate(activeDomain.registered_at) }) }}
                ·
                {{ activeDomain.use_default_nameservers ? $t('app2.domains.dnsYunamo', { site: siteName }) : $t('app2.domains.dnsCustom') }}
                ·
                {{ $t('app2.domains.expires', { date: formatDate(activeDomain.expires_at) }) }}
              </p>
            </div>
            <div class="flex items-center gap-2">
              <button type="button" class="btn btn-outline btn-sm gap-1.5" @click="openRenew(activeDomain)">
                <RefreshCw :size="14" :stroke-width="1.5" />
                {{ $t('app2.domains.renew') }}
              </button>
              <div class="dropdown dropdown-end">
                <div tabindex="0" role="button" class="btn btn-ghost btn-sm btn-square" :title="$t('uiDomains.moreActions')" :aria-label="$t('app2.domains.actions')">
                  <Ellipsis :size="16" :stroke-width="1.5" />
                </div>
                <ul tabindex="0" class="dropdown-content menu z-20 mt-1 w-56 rounded-md p-1.5">
                  <template v-for="item in menuItems(activeDomain)" :key="item.key">
                    <li v-if="item.divider" role="separator" class="pointer-events-none my-1 border-t border-y-line"></li>
                    <li>
                      <button
                        type="button"
                        class="flex items-center gap-2.5 rounded-sm px-3 py-2 text-sm hover:bg-y-surface-2"
                        :class="item.danger ? 'text-y-danger-text' : 'text-y-text'"
                        @click="runMenuItem(item)"
                      >
                        <component :is="item.icon" :size="16" :stroke-width="1.5" :class="item.danger ? '' : 'text-y-faint'" />
                        {{ item.label }}
                      </button>
                    </li>
                  </template>
                </ul>
              </div>
            </div>
          </div>

          <!-- Status + notices -->
          <div class="flex flex-wrap items-center gap-x-4 gap-y-2">
            <button
              v-if="activeDomain.status === 'suspended'"
              type="button"
              class="inline-flex items-center gap-1.5 rounded-sm hover:underline"
              :title="$t('uiDomains.viewSuspension')"
              @click="openSuspendedInfo(activeDomain)"
            >
              <StatusDot :tone="getStatusTone(activeDomain.status)" :label="statusLabel(activeDomain.status)" />
              <Info :size="14" :stroke-width="1.5" class="text-y-faint" />
            </button>
            <StatusDot v-else :tone="getStatusTone(activeDomain.status)" :label="statusLabel(activeDomain.status)" />
            <StatusDot
              :tone="activeDomain.dns_synced ? 'ok' : 'warn'"
              :label="activeDomain.dns_synced ? $t('uiDomains.synced') : $t('uiDomains.notSynced')"
            />
            <span v-if="isExpiringSoon(activeDomain)" class="y-chip-warn !py-0 font-mono text-[11px]">
              {{ $t('uiDomains.daysLeft', { n: getDaysUntilExpiry(activeDomain.expires_at) }) }}
            </span>
            <template v-if="activeDomain.scan_summary">
              <button type="button" :class="getHealthBadgeClass(activeDomain.scan_summary.overall_health)" @click="viewHealthDetails(activeDomain)">
                {{ healthLabel(activeDomain.scan_summary.overall_health) }}
              </button>
              <button
                type="button"
                class="btn btn-ghost btn-xs btn-square text-y-faint"
                :title="$t('domains.scanDetails')"
                :aria-label="$t('domains.scanDetails')"
                @click="viewScanDetails(activeDomain)"
              >
                <ChartColumn :size="14" :stroke-width="1.5" />
              </button>
            </template>
          </div>

          <div v-if="activeNotices.length" class="space-y-1.5">
            <p
              v-for="notice in activeNotices"
              :key="notice.key"
              class="flex items-start gap-2 text-xs leading-5"
              :class="notice.tone === 'danger' ? 'text-y-danger-text' : 'text-y-warn'"
            >
              <TriangleAlert :size="14" :stroke-width="1.5" class="mt-0.5 shrink-0" />
              <span>{{ notice.text }}</span>
            </p>
          </div>

          <!-- DNS mode segmented control -->
          <div role="group" class="y-seg self-start" :aria-label="$t('app2.domains.dnsMode')">
            <button type="button" :aria-pressed="!isCustomMode ? 'true' : 'false'" :disabled="nsSwitching" @click="setMode('yunamo')">
              {{ $t('app2.domains.segYunamo', { site: siteName }) }}
            </button>
            <button type="button" :aria-pressed="isCustomMode ? 'true' : 'false'" :disabled="nsSwitching" @click="setMode('custom')">
              {{ $t('app2.domains.segCustom') }}
            </button>
          </div>

          <!-- Custom nameservers card -->
          <template v-if="isCustomMode">
            <section class="y-panel flex flex-col gap-4 p-5 sm:p-6">
              <h2 class="text-lg font-semibold leading-[26px] text-y-text">{{ $t('app2.ns.customTitle') }}</h2>
              <p class="text-sm text-y-muted">
                {{ activeDomain.use_default_nameservers
                  ? $t('app2.ns.customDescDelegate', { site: siteName })
                  : $t('app2.ns.customDescActive') }}
              </p>
              <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <label v-for="(ns, index) in inlineNS" :key="index" class="y-field text-[13px] text-y-muted">
                  {{ $t('app2.ns.nameserver', { n: index + 1 }) }}
                  <span class="flex gap-2">
                    <input
                      v-model="inlineNS[index]"
                      type="text"
                      :placeholder="$t('uiDomains.nsPlaceholder', { n: index + 1 })"
                      :aria-label="$t('app2.ns.nameserver', { n: index + 1 })"
                      class="input input-bordered min-w-0 flex-1 font-mono text-sm"
                      autocomplete="off"
                      autocapitalize="off"
                      spellcheck="false"
                    />
                    <button
                      v-if="inlineNS.length > 1"
                      type="button"
                      class="btn btn-ghost btn-square shrink-0 text-y-danger-text"
                      :title="$t('uiDomains.nsRemove')"
                      :aria-label="$t('uiDomains.nsRemove')"
                      @click="inlineNS.splice(index, 1)"
                    >
                      <X :size="16" :stroke-width="1.5" />
                    </button>
                  </span>
                </label>
              </div>
              <div class="flex flex-wrap items-center gap-2">
                <button type="button" class="btn btn-primary" :disabled="nsSwitching" @click="saveInlineNS">
                  <span v-if="nsSwitching" class="loading loading-spinner loading-sm"></span>
                  {{ $t('app2.ns.save') }}
                </button>
                <button type="button" class="btn btn-ghost btn-sm gap-1.5" @click="inlineNS.push('')">
                  <Plus :size="16" :stroke-width="1.5" />
                  {{ $t('uiDomains.nsAdd') }}
                </button>
              </div>
              <p v-if="!activeDomain.use_default_nameservers" class="text-xs text-y-faint">
                {{ $t('app2.ns.defaultLabel', { site: siteName }) }}:
                <span class="font-mono">ns1.nodelook.com</span>, <span class="font-mono">ns2.nodelook.com</span>
              </p>
            </section>
            <DnssecCard v-if="!activeDomain.use_default_nameservers" :domain-id="activeDomain.id" custom-ns />
          </template>

          <!-- Yunamo DNS: records + DNSSEC -->
          <template v-else>
            <DnsRecords :domain-id="activeDomain.id" @count="(n) => (recordCounts[activeDomain.id] = n)" />
            <DnssecCard :domain-id="activeDomain.id" />
            <p class="text-[13px] text-y-faint">
              {{ $t('app2.domains.liveNote') }}
              {{ $t('app2.domains.guides') }}
              <a :href="DOCS_PATH" class="text-y-mint-text hover:underline">{{ $t('shell.docs') }}</a>
            </p>
          </template>
        </section>
      </main>
    </div>

    <!-- CyberPanel Hosting Modal -->
    <dialog :class="{ 'modal': true, 'modal-open': showCpModal }">
      <div class="modal-box max-w-lg" v-if="cpModalDomain">
        <h3 class="text-lg font-semibold text-y-text">{{ $t('domains.cpHostingTitle') }}</h3>
        <p class="y-domain mt-1 text-sm !font-normal !text-y-muted">{{ cpModalDomain.full_domain }}</p>

        <!-- Existing account -->
        <div v-if="cpAccountByDomain[cpModalDomain.id]" class="mt-5 space-y-4">
          <div class="grid grid-cols-2 gap-3">
            <div class="y-inset px-4 py-3">
              <p class="y-label">{{ $t('domains.cpHostingStatus') }}</p>
              <span class="mt-2" :class="cpStatusChip(cpAccountByDomain[cpModalDomain.id].status)">{{ cpStatusLabel(cpAccountByDomain[cpModalDomain.id].status) }}</span>
            </div>
            <div class="y-inset px-4 py-3">
              <p class="y-label">{{ $t('domains.cpHostingServer') }}</p>
              <p class="mt-2 text-sm font-medium text-y-text">{{ cpAccountByDomain[cpModalDomain.id].server?.name || '—' }}</p>
            </div>
            <div class="y-inset col-span-2 px-4 py-3">
              <p class="y-label">{{ $t('domains.cpHostingUsername') }}</p>
              <div class="mt-1.5 flex items-center justify-between gap-2">
                <p class="break-all font-mono text-sm font-medium text-y-text">{{ cpAccountByDomain[cpModalDomain.id].cp_username }}</p>
                <button
                  type="button"
                  class="btn btn-ghost btn-xs btn-square"
                  :title="$t('uiDomains.copy')"
                  :aria-label="$t('uiDomains.copy')"
                  @click="copyText(cpAccountByDomain[cpModalDomain.id].cp_username)"
                >
                  <Copy :size="14" :stroke-width="1.5" />
                </button>
              </div>
            </div>
            <div class="y-inset col-span-2 px-4 py-3">
              <p class="y-label">{{ $t('domains.cpHostingPassword') }}</p>
              <div class="mt-1.5 flex items-center justify-between gap-2">
                <p class="min-w-0 flex-1 break-all font-mono text-sm font-medium tracking-wider text-y-text">
                  <span v-if="cpCredentials">{{ showCpPassword ? cpCredentials.cp_password : '••••••••' }}</span>
                  <span v-else class="font-sans text-xs font-normal tracking-normal text-y-faint">{{ $t('domains.cpPasswordHidden') }}</span>
                </p>
                <div class="flex shrink-0 gap-1">
                  <button
                    type="button"
                    class="btn btn-ghost btn-xs gap-1"
                    :disabled="cpCredentialsLoading"
                    @click="fetchCpCredentials(cpAccountByDomain[cpModalDomain.id])"
                  >
                    <span v-if="cpCredentialsLoading" class="loading loading-spinner loading-xs"></span>
                    <template v-else-if="!cpCredentials"><Eye :size="14" :stroke-width="1.5" />{{ $t('domains.cpPasswordShow') }}</template>
                    <template v-else>
                      <EyeOff v-if="showCpPassword" :size="14" :stroke-width="1.5" />
                      <Eye v-else :size="14" :stroke-width="1.5" />
                      {{ showCpPassword ? $t('domains.cpPasswordHide') : $t('domains.cpPasswordShow') }}
                    </template>
                  </button>
                  <button
                    v-if="cpCredentials"
                    type="button"
                    class="btn btn-ghost btn-xs btn-square"
                    :title="$t('uiDomains.copy')"
                    :aria-label="$t('uiDomains.copy')"
                    @click="copyText(cpCredentials.cp_password)"
                  >
                    <Copy :size="14" :stroke-width="1.5" />
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div v-if="cpAccountByDomain[cpModalDomain.id].error_msg" class="alert alert-warning items-start text-sm">
            <TriangleAlert :size="16" :stroke-width="1.5" class="mt-0.5 shrink-0" />
            <span>{{ cpAccountByDomain[cpModalDomain.id].error_msg }}</span>
          </div>

          <div class="modal-action flex-wrap gap-2">
            <button type="button" class="btn btn-ghost" @click="closeCpModal">{{ $t('common.close') }}</button>
            <button type="button" class="btn btn-outline text-y-danger-text" :disabled="cpSubmitting" @click="confirmDeleteCpAccount">
              <span v-if="cpSubmitting" class="loading loading-spinner loading-sm"></span>
              {{ $t('domains.cpHostingDelete') }}
            </button>
            <button type="button" class="btn btn-primary gap-1.5" :disabled="cpCredentialsLoading" @click="openCpPanel(cpAccountByDomain[cpModalDomain.id])">
              <span v-if="cpCredentialsLoading" class="loading loading-spinner loading-sm"></span>
              <ExternalLink v-else :size="16" :stroke-width="1.5" />
              {{ $t('domains.cpHostingOpenPanel') }}
            </button>
          </div>
        </div>

        <!-- Apply: choose a server -->
        <div v-else class="mt-5 space-y-4">
          <p class="text-sm text-y-muted">{{ $t('domains.cpHostingApply') }}</p>

          <YLoader v-if="cpServersLoading" :size="28" />
          <p v-else-if="cpServers.length === 0" class="y-inset px-4 py-6 text-center text-sm text-y-muted">
            {{ $t('domains.cpNoServersAvailable') }}
          </p>
          <div v-else class="space-y-2">
            <p class="y-field-label">{{ $t('domains.cpHostingChooseServer') }}</p>
            <label
              v-for="srv in cpServers"
              :key="srv.id"
              class="flex items-center gap-3 rounded-md border px-4 py-3 transition-colors"
              :class="[
                !srv.available ? 'cursor-not-allowed border-y-line text-y-faint' :
                cpSelectedServer === srv.id ? 'y-mint-soft cursor-pointer' : 'cursor-pointer border-y-line hover:border-y-line-strong hover:bg-y-surface-2'
              ]"
              @click="srv.available && (cpSelectedServer = srv.id)"
            >
              <input v-model="cpSelectedServer" type="radio" :value="srv.id" :disabled="!srv.available" class="radio radio-primary radio-sm" />
              <div class="min-w-0 flex-1">
                <p class="text-sm font-medium" :class="srv.available ? 'text-y-text' : 'text-y-faint'">{{ srv.name }}</p>
                <p class="font-mono text-xs text-y-faint">
                  {{ srv.current_accounts }} / {{ srv.max_accounts === 0 ? '∞' : srv.max_accounts }} {{ $t('domains.cpAccountsUsed') }}
                </p>
              </div>
              <span v-if="!srv.available" class="y-chip-danger">{{ $t('domains.cpServerFull') }}</span>
            </label>
          </div>

          <div v-if="cpFormError" class="alert alert-error text-sm">{{ cpFormError }}</div>

          <div class="modal-action">
            <button type="button" class="btn btn-ghost" @click="closeCpModal">{{ $t('common.cancel') }}</button>
            <button type="button" class="btn btn-primary" :disabled="cpSubmitting || !cpSelectedServer || cpServers.length === 0" @click="createCpAccount">
              <span v-if="cpSubmitting" class="loading loading-spinner loading-sm"></span>
              {{ $t('domains.cpApplyHosting') }}
            </button>
          </div>
        </div>
      </div>
      <form method="dialog" class="modal-backdrop" @click="closeCpModal"></form>
    </dialog>

    <!-- CyberPanel Delete Confirm Modal -->
    <dialog :class="{ 'modal': true, 'modal-open': showCpDeleteConfirm }">
      <div class="modal-box max-w-md">
        <h3 class="text-lg font-semibold text-y-text">{{ $t('domains.cpHostingDelete') }}</h3>
        <p class="mt-2 text-sm leading-6 text-y-muted">{{ $t('domains.cpHostingDeleteConfirm') }}</p>
        <div class="modal-action">
          <button type="button" class="btn btn-ghost" @click="showCpDeleteConfirm = false">{{ $t('common.cancel') }}</button>
          <button type="button" class="btn btn-error" :disabled="cpSubmitting" @click="deleteCpAccount">
            <span v-if="cpSubmitting" class="loading loading-spinner loading-sm"></span>
            {{ $t('admin.delete') }}
          </button>
        </div>
      </div>
    </dialog>

    <!-- Modify Nameservers Modal -->
    <dialog :class="{ 'modal': true, 'modal-open': showNSModal }">
      <div class="modal-box max-w-lg" v-if="selectedDomain">
        <h3 class="text-lg font-semibold text-y-text">{{ $t('domains.modifyNameservers') }}</h3>
        <p class="mt-1 text-sm text-y-muted">{{ $t('domains.domain') }}: <span class="y-domain">{{ selectedDomain.full_domain }}</span></p>

        <label class="mt-5 flex cursor-pointer items-start gap-3 rounded-md border border-y-line px-4 py-3">
          <input v-model="useCustomNS" type="checkbox" class="toggle toggle-primary toggle-sm mt-0.5" />
          <span class="min-w-0">
            <span class="block text-sm font-medium text-y-text">{{ $t('uiDomains.nsUseCustom') }}</span>
            <span class="mt-0.5 block text-xs leading-5 text-y-faint">{{ $t('uiDomains.nsUseCustomHint') }}</span>
          </span>
        </label>

        <!-- Default nameservers (read-only) -->
        <div v-if="!useCustomNS" class="mt-5 y-field">
          <span class="y-field-label">{{ $t('uiDomains.nsDefaultLabel') }}</span>
          <div class="space-y-2">
            <input
              v-for="(ns, index) in ['ns1.nodelook.com', 'ns2.nodelook.com']"
              :key="index"
              :value="ns"
              type="text"
              class="input input-bordered w-full font-mono text-sm text-y-muted"
              readonly
              disabled
            />
          </div>
        </div>

        <!-- Custom nameservers (editable) -->
        <div v-else class="mt-5 y-field">
          <span class="y-field-label">{{ $t('uiDomains.nsCustomLabel') }}</span>
          <div class="space-y-2">
            <div v-for="(ns, index) in nameservers" :key="index" class="flex gap-2">
              <input
                v-model="nameservers[index]"
                type="text"
                :placeholder="$t('uiDomains.nsPlaceholder', { n: index + 1 })"
                :aria-label="$t('uiDomains.nsPlaceholder', { n: index + 1 })"
                class="input input-bordered min-w-0 flex-1 font-mono text-sm"
                autocomplete="off"
                autocapitalize="off"
                spellcheck="false"
              />
              <button
                v-if="nameservers.length > 1"
                type="button"
                class="btn btn-ghost btn-square text-y-danger-text"
                :title="$t('uiDomains.nsRemove')"
                :aria-label="$t('uiDomains.nsRemove')"
                @click="removeNameserver(index)"
              >
                <X :size="16" :stroke-width="1.5" />
              </button>
            </div>
          </div>
          <div>
            <button type="button" class="btn btn-ghost btn-sm gap-1.5" @click="addNameserver">
              <Plus :size="16" :stroke-width="1.5" />
              {{ $t('uiDomains.nsAdd') }}
            </button>
          </div>
        </div>

        <div class="modal-action">
          <button type="button" class="btn btn-ghost" @click="closeNSModal">{{ $t('common.cancel') }}</button>
          <button type="button" class="btn btn-primary" :disabled="submitting" @click="saveNameservers">
            <span v-if="submitting" class="loading loading-spinner loading-sm"></span>
            <span v-else>{{ $t('common.save') }}</span>
          </button>
        </div>
      </div>
      <form method="dialog" class="modal-backdrop">
        <button type="button" @click="closeNSModal">close</button>
      </form>
    </dialog>

    <!-- Renew Domain Modal -->
    <dialog :class="{ 'modal': true, 'modal-open': showRenewModal }">
      <div class="modal-box max-w-lg" v-if="selectedDomain">
        <h3 class="text-lg font-semibold text-y-text">{{ $t('domains.renewDomainTitle') }}</h3>
        <p class="mt-1 text-sm text-y-muted">{{ $t('domains.domain') }}: <span class="y-domain">{{ selectedDomain.full_domain }}</span></p>

        <div class="mt-5 grid grid-cols-2 gap-3">
          <div class="y-inset px-4 py-3">
            <p class="y-label">{{ $t('domains.currentExpiration') }}</p>
            <p class="mt-1.5 font-mono text-sm text-y-text">{{ formatDate(selectedDomain.expires_at) }}</p>
          </div>
          <div class="y-mint-soft rounded-md border px-4 py-3">
            <p class="y-label">{{ $t('domains.newExpiration') }}</p>
            <p class="mt-1.5 font-mono text-sm text-y-mint-text">{{ calculateNewExpiry(selectedDomain.expires_at, renewYears) }}</p>
          </div>
        </div>

        <div class="mt-5 y-field">
          <div class="flex items-baseline justify-between gap-3">
            <span class="y-field-label">{{ $t('domains.renewalPeriod') }}</span>
            <span class="font-mono text-sm text-y-text">{{ $t('domains.yearCount', { count: renewYears }) }}</span>
          </div>
          <input
            v-model.number="renewYears"
            type="range"
            min="1"
            max="10"
            class="range range-primary range-sm"
            :disabled="renewIsLifetime"
            :aria-label="$t('domains.renewalPeriod')"
          />
          <div class="flex justify-between font-mono text-xs text-y-faint">
            <span>1 {{ $t('domains.year') }}</span>
            <span>10 {{ $t('domains.years') }}</span>
          </div>
        </div>

        <!-- Lifetime option (paid domains) -->
        <label
          v-if="selectedDomain.root_domain && !selectedDomain.root_domain.is_free && selectedDomain.root_domain.lifetime_price"
          class="mt-4 flex cursor-pointer items-start gap-3 rounded-md border border-y-line px-4 py-3"
        >
          <input v-model="renewIsLifetime" type="checkbox" class="checkbox checkbox-sm mt-0.5" />
          <span class="min-w-0">
            <span class="block text-sm font-medium text-y-text">{{ $t('domains.lifetimeRenewal') }}</span>
            <span class="block text-xs text-y-faint">{{ $t('domains.lifetimeRenewalDesc') }}</span>
          </span>
        </label>

        <!-- Coupon code (paid domains) -->
        <div v-if="selectedDomain.root_domain && !selectedDomain.root_domain.is_free" class="mt-5 y-field">
          <span class="y-field-label">{{ $t('uiDomains.couponLabel') }} <span class="font-normal text-y-faint">({{ $t('uiDomains.optional') }})</span></span>
          <div class="join w-full">
            <input
              v-model="renewCouponCode"
              type="text"
              :placeholder="$t('coupon.enterCode')"
              :aria-label="$t('uiDomains.couponLabel')"
              class="input input-bordered join-item min-w-0 flex-1 font-mono"
              autocomplete="off"
              autocapitalize="off"
              spellcheck="false"
              @keyup.enter="applyRenewCoupon"
            />
            <button type="button" class="btn btn-outline join-item" :disabled="!renewCouponCode || renewCouponApplying" @click="applyRenewCoupon">
              <span v-if="renewCouponApplying" class="loading loading-spinner loading-xs"></span>
              <span v-else>{{ $t('coupon.apply') }}</span>
            </button>
          </div>
          <p v-if="renewCouponError" class="text-xs text-y-danger-text">{{ renewCouponError }}</p>
          <p v-if="renewCouponApplied" class="flex items-center gap-1 text-xs text-y-mint-text">
            <Check :size="14" :stroke-width="2" />
            {{ $t('order.couponApplied') }}
          </p>
        </div>

        <!-- Price -->
        <div v-if="selectedDomain.root_domain && !selectedDomain.root_domain.is_free" class="mt-5 y-inset space-y-2 px-4 py-4">
          <div class="flex items-center justify-between text-sm">
            <span class="text-y-muted">{{ $t('order.originalPrice') }}</span>
            <span class="font-mono text-y-text">{{ formatPrice(calculateRenewPrice()) }}</span>
          </div>
          <div v-if="renewPriceData && renewPriceData.discount_amount > 0" class="flex items-center justify-between text-sm">
            <span class="text-y-muted">{{ $t('order.discount') }}</span>
            <span class="font-mono text-y-mint-text">-{{ formatPrice(renewPriceData.discount_amount) }}</span>
          </div>
          <div class="y-divider !my-3"></div>
          <div class="flex items-center justify-between">
            <span class="text-sm font-medium text-y-text">{{ $t('order.finalPrice') }}</span>
            <span class="font-mono text-2xl font-medium tracking-tight text-y-text">{{ formatPrice(renewPriceData ? renewPriceData.final_price : calculateRenewPrice()) }}</span>
          </div>
        </div>

        <div class="modal-action">
          <button type="button" class="btn btn-ghost" @click="closeRenewModal">{{ $t('common.cancel') }}</button>
          <button type="button" class="btn btn-primary" :disabled="submitting" @click="renewDomain">
            <span v-if="submitting" class="loading loading-spinner loading-sm"></span>
            <span v-else>{{ $t('domains.renew') }}</span>
          </button>
        </div>
      </div>
      <form method="dialog" class="modal-backdrop">
        <button type="button" @click="closeRenewModal">close</button>
      </form>
    </dialog>

    <!-- Transfer Domain Modal -->
    <dialog :class="{ 'modal': true, 'modal-open': showTransferModal }">
      <div class="modal-box max-w-lg" v-if="selectedDomain">
        <h3 class="text-lg font-semibold text-y-text">{{ $t('domains.transferDomainTitle') }}</h3>
        <p class="mt-1 text-sm text-y-muted">{{ $t('domains.domain') }}: <span class="y-domain">{{ selectedDomain.full_domain }}</span></p>

        <div class="alert alert-warning mt-5 items-start">
          <TriangleAlert :size="18" :stroke-width="1.5" class="mt-0.5 shrink-0" />
          <div>
            <p class="text-sm font-medium">{{ $t('uiDomains.transferWarnTitle') }}</p>
            <p class="mt-0.5 text-sm">{{ $t('uiDomains.transferWarnDesc') }}</p>
          </div>
        </div>

        <label class="mt-5 y-field">
          <span class="y-field-label">{{ $t('uiDomains.transferTarget') }}</span>
          <input
            v-model="transferTarget"
            type="text"
            :placeholder="$t('uiDomains.transferPlaceholder')"
            class="input input-bordered w-full font-mono"
            autocomplete="off"
            autocapitalize="off"
            spellcheck="false"
          />
          <span class="y-field-hint">{{ $t('uiDomains.transferHint', { site: siteName }) }}</span>
        </label>

        <div class="modal-action">
          <button type="button" class="btn btn-ghost" @click="closeTransferModal">{{ $t('common.cancel') }}</button>
          <button type="button" class="btn btn-error" :disabled="submitting || !transferTarget" @click="transferDomain">
            <span v-if="submitting" class="loading loading-spinner loading-sm"></span>
            <span v-else>{{ $t('domains.transfer') }}</span>
          </button>
        </div>
      </div>
      <form method="dialog" class="modal-backdrop">
        <button type="button" @click="closeTransferModal">close</button>
      </form>
    </dialog>

    <!-- FOSSBilling Sync Modal -->
    <dialog :class="{ 'modal': true, 'modal-open': showSyncModal }">
      <div class="modal-box max-w-2xl">
        <h3 class="text-lg font-semibold text-y-text">{{ $t('uiDomains.syncTitle') }}</h3>
        <p class="mt-1 text-sm text-y-muted">{{ $t('uiDomains.syncDesc') }}</p>

        <div class="mt-5 space-y-4">
          <label v-if="!siteConfig.fossbilling?.url" class="y-field">
            <span class="y-field-label">{{ $t('uiDomains.syncUrl') }}</span>
            <input
              v-model="syncForm.fossbilling_url"
              type="text"
              placeholder="https://your-fossbilling-server.com"
              class="input input-bordered w-full font-mono"
              :disabled="syncInProgress"
              autocomplete="off"
              autocapitalize="off"
              spellcheck="false"
            />
            <span class="y-field-hint">{{ $t('uiDomains.syncUrlHint') }}</span>
          </label>

          <div v-if="siteConfig.fossbilling?.url" class="alert alert-info items-start">
            <Info :size="16" :stroke-width="1.5" class="mt-0.5 shrink-0" />
            <span class="text-sm">{{ $t('uiDomains.syncFrom') }}: <span class="break-all font-mono">{{ siteConfig.fossbilling.url }}</span></span>
          </div>

          <label class="y-field">
            <span class="y-field-label">{{ $t('uiDomains.syncKey') }}</span>
            <input
              v-model="syncForm.fossbilling_api_key"
              type="text"
              :placeholder="$t('uiDomains.syncKeyPlaceholder')"
              class="input input-bordered w-full font-mono"
              :disabled="syncInProgress"
              autocomplete="off"
              autocapitalize="off"
              spellcheck="false"
            />
            <span class="y-field-hint">{{ $t('uiDomains.syncKeyHint') }}</span>
          </label>

          <!-- Sync results -->
          <div v-if="syncResult" class="space-y-3">
            <div class="alert items-start" :class="syncResult.error_count > 0 ? 'alert-warning' : 'alert-success'">
              <TriangleAlert v-if="syncResult.error_count > 0" :size="18" :stroke-width="1.5" class="mt-0.5 shrink-0" />
              <CircleCheck v-else :size="18" :stroke-width="1.5" class="mt-0.5 shrink-0 text-y-mint-text" />
              <div class="min-w-0">
                <p class="text-sm font-medium">{{ syncResult.message }}</p>
                <p class="mt-1 flex flex-wrap gap-x-4 gap-y-1 font-mono text-xs">
                  <span>{{ $t('uiDomains.syncSynced') }} {{ syncResult.synced_count }}</span>
                  <span>{{ $t('uiDomains.syncExisting') }} {{ syncResult.existing_count }}</span>
                  <span>{{ $t('uiDomains.syncSkipped') }} {{ syncResult.skipped_count }}</span>
                  <span>{{ $t('uiDomains.syncErrors') }} {{ syncResult.error_count }}</span>
                </p>
              </div>
            </div>

            <div v-if="syncResult.details && syncResult.details.length > 0" class="y-inset max-h-60 overflow-y-auto px-4 py-3">
              <p class="y-label mb-2">{{ $t('uiDomains.syncDetails') }}</p>
              <ul class="space-y-1 font-mono text-xs text-y-muted">
                <li v-for="(detail, index) in syncResult.details" :key="index">{{ detail }}</li>
              </ul>
            </div>
          </div>
        </div>

        <div class="modal-action">
          <button type="button" class="btn btn-ghost" :disabled="syncInProgress" @click="closeSyncModal">{{ $t('common.cancel') }}</button>
          <button
            type="button"
            class="btn btn-primary"
            :disabled="syncInProgress || (!syncForm.fossbilling_url && !siteConfig.fossbilling?.url) || !syncForm.fossbilling_api_key"
            @click="syncFromFOSSBilling"
          >
            <span v-if="syncInProgress" class="loading loading-spinner loading-sm"></span>
            <span v-else>{{ $t('uiDomains.syncAction') }}</span>
          </button>
        </div>
      </div>
      <form method="dialog" class="modal-backdrop">
        <button type="button" :disabled="syncInProgress" @click="closeSyncModal">close</button>
      </form>
    </dialog>

    <!-- Health Details Modal -->
    <dialog :class="{ 'modal': true, 'modal-open': showHealthDetailsModal }">
      <div class="modal-box max-w-2xl" v-if="selectedDomain && selectedDomain.scan_summary">
        <h3 class="text-lg font-semibold text-y-text">{{ $t('domains.healthDetails') }}</h3>
        <p class="mt-1 text-sm text-y-muted">{{ $t('domains.domain') }}: <span class="y-domain">{{ selectedDomain.full_domain }}</span></p>

        <div class="mt-5 y-inset flex items-center justify-between gap-4 px-4 py-4">
          <div class="min-w-0">
            <p class="text-sm font-medium text-y-text">{{ $t('domains.overallHealth') }}</p>
            <p class="mt-0.5 text-xs text-y-faint">{{ $t('domains.overallHealthDesc') }}</p>
          </div>
          <span class="shrink-0" :class="getHealthBadgeClass(selectedDomain.scan_summary.overall_health)">
            {{ healthLabel(selectedDomain.scan_summary.overall_health) }}
          </span>
        </div>

        <ul class="mt-4 divide-y divide-y-line rounded-md border border-y-line">
          <li v-for="check in healthChecks" :key="check.key" class="flex items-center justify-between gap-4 px-4 py-3">
            <div class="flex min-w-0 items-start gap-3">
              <component :is="check.icon" :size="18" :stroke-width="1.5" class="mt-0.5 shrink-0 text-y-faint" />
              <div class="min-w-0">
                <p class="text-sm font-medium text-y-text">{{ check.title }}</p>
                <p class="mt-0.5 text-xs text-y-faint">{{ check.desc }}</p>
              </div>
            </div>
            <span class="shrink-0" :class="check.cls">{{ check.value || $t('uiDomains.health.unknown') }}</span>
          </li>
          <li class="flex items-center justify-between gap-4 px-4 py-3">
            <div class="flex min-w-0 items-start gap-3">
              <Activity :size="18" :stroke-width="1.5" class="mt-0.5 shrink-0 text-y-faint" />
              <div class="min-w-0">
                <p class="text-sm font-medium text-y-text">{{ $t('domains.uptimePercentage') }}</p>
                <p class="mt-0.5 text-xs text-y-faint">{{ $t('domains.uptimePercentageDesc') }}</p>
              </div>
            </div>
            <span class="shrink-0 font-mono text-lg font-medium" :class="getUptimeClass(selectedDomain.scan_summary.uptime_percentage)">
              {{ selectedDomain.scan_summary.uptime_percentage ? selectedDomain.scan_summary.uptime_percentage.toFixed(2) + '%' : $t('uiDomains.notAvailable') }}
            </span>
          </li>
        </ul>

        <div class="mt-4 grid grid-cols-2 gap-3">
          <div class="y-inset px-4 py-3">
            <p class="y-label">{{ $t('domains.totalScans') }}</p>
            <p class="mt-1.5 font-mono text-2xl font-medium tracking-tight text-y-text">{{ selectedDomain.scan_summary.total_scans || 0 }}</p>
          </div>
          <div class="y-inset px-4 py-3">
            <p class="y-label">{{ $t('domains.successfulScans') }}</p>
            <p class="mt-1.5 font-mono text-2xl font-medium tracking-tight text-y-mint-text">{{ selectedDomain.scan_summary.successful_scans || 0 }}</p>
          </div>
        </div>

        <p v-if="selectedDomain.scan_summary.last_scanned_at" class="mt-4 text-xs text-y-faint">
          {{ $t('domains.lastScanned') }}: <span class="font-mono">{{ new Date(selectedDomain.scan_summary.last_scanned_at).toLocaleString() }}</span>
        </p>

        <div class="modal-action">
          <button type="button" class="btn btn-ghost" @click="closeHealthDetailsModal">{{ $t('common.close') }}</button>
        </div>
      </div>
      <form method="dialog" class="modal-backdrop">
        <button type="button" @click="closeHealthDetailsModal">close</button>
      </form>
    </dialog>

    <!-- Scan Details Modal -->
    <dialog :class="{ 'modal': true, 'modal-open': showScanDetailsModal }">
      <div class="modal-box max-w-5xl" v-if="selectedDomain">
        <h3 class="text-lg font-semibold text-y-text">{{ $t('domains.scanDetails') }}</h3>
        <p class="mt-1 text-sm text-y-muted">{{ $t('domains.domain') }}: <span class="y-domain">{{ selectedDomain.full_domain }}</span></p>

        <!-- Summary -->
        <div v-if="selectedDomain.scan_summary" class="mt-5 grid grid-cols-2 gap-px overflow-hidden rounded-md border border-y-line bg-y-line md:grid-cols-4">
          <div class="bg-y-bg px-4 py-3">
            <p class="y-label">{{ $t('domains.overallHealth') }}</p>
            <span class="mt-2" :class="getHealthBadgeClass(selectedDomain.scan_summary.overall_health)">{{ healthLabel(selectedDomain.scan_summary.overall_health) }}</span>
          </div>
          <div class="bg-y-bg px-4 py-3">
            <p class="y-label">{{ $t('uiDomains.scanSafeBrowsing') }}</p>
            <span class="mt-2" :class="getSafeBrowsingBadgeClass(selectedDomain.scan_summary.safe_browsing_status)">{{ selectedDomain.scan_summary.safe_browsing_status || $t('uiDomains.notAvailable') }}</span>
          </div>
          <div class="bg-y-bg px-4 py-3">
            <p class="y-label">{{ $t('uiDomains.scanVirusTotal') }}</p>
            <span class="mt-2" :class="getVirusTotalBadgeClass(selectedDomain.scan_summary.virustotal_status)">{{ selectedDomain.scan_summary.virustotal_status || $t('uiDomains.notAvailable') }}</span>
          </div>
          <div class="bg-y-bg px-4 py-3">
            <p class="y-label">{{ $t('uiDomains.scanUptime') }}</p>
            <p class="mt-1.5 font-mono text-sm font-medium text-y-text">
              {{ selectedDomain.scan_summary.uptime_percentage ? selectedDomain.scan_summary.uptime_percentage.toFixed(2) + '%' : $t('uiDomains.notAvailable') }}
            </p>
          </div>
        </div>

        <!-- Records -->
        <div class="mt-4">
          <YLoader v-if="scanLoading" :size="28" :label="$t('uiDomains.scanLoading')" />

          <div v-else-if="scanRecords.length > 0" class="overflow-x-auto rounded-md border border-y-line">
            <table class="y-table text-[13px]">
              <thead>
                <tr>
                  <th>{{ $t('uiDomains.scanTime') }}</th>
                  <th>{{ $t('uiDomains.scanStatus') }}</th>
                  <th>{{ $t('uiDomains.scanHttp') }}</th>
                  <th>{{ $t('uiDomains.scanDns') }}</th>
                  <th>{{ $t('uiDomains.scanSsl') }}</th>
                  <th>{{ $t('uiDomains.scanSafeBrowsing') }}</th>
                  <th>{{ $t('uiDomains.scanVirusTotal') }}</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="scan in scanRecords" :key="scan.id">
                  <td class="whitespace-nowrap font-mono text-xs text-y-muted">{{ formatDateTime(scan.scanned_at) }}</td>
                  <td class="whitespace-nowrap"><span :class="getScanStatusBadgeClass(scan.status)">{{ scan.status }}</span></td>
                  <td class="whitespace-nowrap"><span :class="getStatusBadgeClass(scan.http_status)">{{ scan.http_status || $t('uiDomains.notAvailable') }}</span></td>
                  <td class="whitespace-nowrap"><span :class="getStatusBadgeClass(scan.dns_status)">{{ scan.dns_status || $t('uiDomains.notAvailable') }}</span></td>
                  <td class="whitespace-nowrap"><span :class="getStatusBadgeClass(scan.ssl_status)">{{ scan.ssl_status || $t('uiDomains.notAvailable') }}</span></td>
                  <td class="whitespace-nowrap"><span :class="getSafeBrowsingBadgeClass(scan.safe_browsing_status)">{{ scan.safe_browsing_status || $t('uiDomains.notAvailable') }}</span></td>
                  <td class="whitespace-nowrap"><span :class="getVirusTotalBadgeClass(scan.virustotal_status)">{{ scan.virustotal_status || $t('uiDomains.notAvailable') }}</span></td>
                </tr>
              </tbody>
            </table>
          </div>

          <p v-else class="y-inset px-4 py-8 text-center text-sm text-y-muted">{{ $t('uiDomains.scanEmpty') }}</p>
        </div>

        <!-- Pagination -->
        <nav v-if="scanTotalPages > 1" class="mt-4 flex items-center justify-center gap-1">
          <button
            type="button"
            class="btn btn-ghost btn-sm btn-square"
            :disabled="scanPage === 1 || scanLoading"
            :title="$t('uiDomains.prevPage')"
            :aria-label="$t('uiDomains.prevPage')"
            @click="changeScanPage(scanPage - 1)"
          >
            <ChevronLeft :size="16" :stroke-width="1.5" />
          </button>
          <template v-for="page in visibleScanPages" :key="page">
            <button
              v-if="page !== '...'"
              type="button"
              class="btn btn-ghost btn-sm min-w-[2.125rem] px-2 font-mono font-medium"
              :class="page === scanPage ? 'bg-y-surface-2 !text-y-text' : '!text-y-muted'"
              :aria-current="page === scanPage ? 'page' : undefined"
              :disabled="scanLoading"
              @click="changeScanPage(page)"
            >{{ page }}</button>
            <span v-else class="px-1 font-mono text-sm text-y-faint">…</span>
          </template>
          <button
            type="button"
            class="btn btn-ghost btn-sm btn-square"
            :disabled="scanPage === scanTotalPages || scanLoading"
            :title="$t('uiDomains.nextPage')"
            :aria-label="$t('uiDomains.nextPage')"
            @click="changeScanPage(scanPage + 1)"
          >
            <ChevronRight :size="16" :stroke-width="1.5" />
          </button>
        </nav>

        <div class="modal-action">
          <button type="button" class="btn btn-ghost" @click="closeScanDetailsModal">{{ $t('common.close') }}</button>
        </div>
      </div>
      <form method="dialog" class="modal-backdrop">
        <button type="button" @click="closeScanDetailsModal">close</button>
      </form>
    </dialog>

    <!-- Suspended Info Modal -->
    <dialog :class="{ 'modal': true, 'modal-open': showSuspendedInfoModal }">
      <div class="modal-box max-w-md">
        <h3 class="flex items-center gap-2 text-lg font-semibold text-y-text">
          <span class="y-dot bg-y-warn" aria-hidden="true"></span>
          {{ $t('uiDomains.suspendedTitle') }}
        </h3>
        <p v-if="suspendedInfoDomain" class="y-domain mt-1 text-sm !font-normal !text-y-muted">{{ suspendedInfoDomain.full_domain }}</p>
        <p class="mt-4 text-sm leading-6 text-y-muted">{{ $t('domains.suspendedNotice') }}</p>
        <div v-if="suspendedInfoDomain?.suspend_reason" class="mt-4 y-inset px-4 py-3">
          <p class="y-label">{{ $t('domains.suspendReasonLabel') }}</p>
          <p class="mt-1.5 text-sm text-y-text">{{ suspendedInfoDomain.suspend_reason }}</p>
        </div>
        <div class="modal-action">
          <button type="button" class="btn btn-ghost" @click="showSuspendedInfoModal = false">{{ $t('common.close') }}</button>
        </div>
      </div>
      <form method="dialog" class="modal-backdrop">
        <button type="button" @click="showSuspendedInfoModal = false">close</button>
      </form>
    </dialog>

    <!-- Delete Domain Confirm Modal -->
    <dialog :class="{ 'modal': true, 'modal-open': showDeleteModal }">
      <div class="modal-box max-w-md">
        <h3 class="text-lg font-semibold text-y-text">{{ $t('uiDomains.deleteTitle') }}</h3>
        <p class="mt-2 text-sm leading-6 text-y-muted">{{ $t('domains.deleteTypeConfirm') }}</p>
        <p class="y-domain y-inset mt-4 select-all px-3 py-2 text-sm">{{ deleteTargetDomain?.full_domain }}</p>
        <input
          v-model="deleteConfirmInput"
          type="text"
          class="input input-bordered mt-3 w-full font-mono"
          :placeholder="$t('domains.deleteTypeConfirmPlaceholder')"
          :aria-label="$t('domains.deleteTypeConfirmPlaceholder')"
          autocomplete="off"
          autocapitalize="off"
          spellcheck="false"
          @keyup.enter="executeDelete"
        />
        <div class="modal-action">
          <button type="button" class="btn btn-ghost" :disabled="deleting" @click="showDeleteModal = false">{{ $t('common.cancel') }}</button>
          <button
            type="button"
            class="btn btn-error"
            :disabled="deleting || deleteConfirmInput !== deleteTargetDomain?.full_domain"
            @click="executeDelete"
          >
            <span v-if="deleting" class="loading loading-spinner loading-sm"></span>
            {{ $t('domains.delete') }}
          </button>
        </div>
      </div>
      <form method="dialog" class="modal-backdrop">
        <button type="button" @click="showDeleteModal = false">close</button>
      </form>
    </dialog>
  </div>
</template>
<script setup>
import { ref, onMounted, computed, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import {
  Plus, Search, Info, TriangleAlert, RefreshCw, Ellipsis, Server, Activity, ChartColumn,
  ArrowLeftRight, Trash2, Copy, Eye, EyeOff, ExternalLink, X, Check, CircleCheck, Globe, Network,
  Lock, ShieldCheck, Bug, ChevronLeft, ChevronRight, SquareArrowOutUpRight,
} from 'lucide-vue-next'
import StatusDot from '../components/ui/StatusDot.vue'
import EmptyState from '../components/ui/EmptyState.vue'
import YLoader from '../components/brand/YLoader.vue'
import DnsRecords from '../components/domains/DnsRecords.vue'
import DnssecCard from '../components/domains/DnssecCard.vue'
import axios from '../utils/axios'
import { useToast } from '../composables/useToast'
import { useCurrency } from '../composables/useCurrency'
import { formatDate as formatDateUtil, formatDateTime, daysUntilExpiry, addYears } from '../utils/time'
import { useSiteConfigStore } from '../stores/siteConfig'
import { useAuthStore } from '../stores/auth'
import { DOCS_PATH } from '../config/links'

const route = useRoute()
const router = useRouter()
const { t, te } = useI18n()
const toast = useToast()
const { formatPrice } = useCurrency()
const siteConfig = useSiteConfigStore()

// 确保加载站点配置
if (!siteConfig.loaded) {
  siteConfig.fetch()
}

// FOSSBilling 是否启用
const fossbillingEnabled = computed(() => siteConfig.fossbilling?.enabled || false)

const domains = ref([])
const loading = ref(true)
const submitting = ref(false)

// Modal states
const showNSModal = ref(false)
const showRenewModal = ref(false)
const showTransferModal = ref(false)
const showSyncModal = ref(false)
const showScanDetailsModal = ref(false)
const showHealthDetailsModal = ref(false)
const showDeleteModal = ref(false)
const deleteTargetDomain = ref(null)
const deleteConfirmInput = ref('')
const deleting = ref(false)
const showSuspendedInfoModal = ref(false)
const suspendedInfoDomain = ref(null)
const selectedDomain = ref(null)

// NS modification (modal)
const nameservers = ref(['', ''])
const useCustomNS = ref(false)

// Inline DNS mode (reference segmented control)
const recordCounts = ref({})
const segOverride = ref(null) // null = follow the domain's saved state, 'custom' = show NS editor
const inlineNS = ref(['', ''])
const nsSwitching = ref(false)

// Renew
const renewYears = ref(1)
const renewIsLifetime = ref(false)
const renewCouponCode = ref('')
const renewCouponApplying = ref(false)
const renewCouponApplied = ref(false)
const renewCouponError = ref('')
const renewPriceData = ref(null)

// Transfer
const transferTarget = ref('')

// FOSSBilling Sync
const syncInProgress = ref(false)
const syncForm = ref({
  fossbilling_url: '',
  fossbilling_api_key: ''
})
const syncResult = ref(null)

// Scan Details
const scanRecords = ref([])
const scanLoading = ref(false)
const scanPage = ref(1)
const scanPageSize = ref(10)
const scanTotalPages = ref(1)

// CyberPanel Hosting
const cpAccounts = ref([])
const cpServers = ref([])
const cpServersLoading = ref(false)
const cpSelectedServer = ref(null)
const showCpModal = ref(false)
const showCpDeleteConfirm = ref(false)
const cpModalDomain = ref(null)
const cpSubmitting = ref(false)
const cpFormError = ref('')
const cpCredentials = ref(null)       // { cp_username, cp_password, login_url }
const cpCredentialsLoading = ref(false)
const showCpPassword = ref(false)

const cpAccountByDomain = computed(() => {
  const map = {}
  for (const acc of cpAccounts.value) {
    if (acc.status !== 'terminated') {
      map[acc.domain_id] = acc
    }
  }
  return map
})

const closeCpModal = () => {
  showCpModal.value = false
  cpCredentials.value = null
  showCpPassword.value = false
}

const fetchCpAccounts = async () => {
  try {
    const res = await axios.get('/api/cyberpanel/accounts')
    cpAccounts.value = res.data.accounts || []
  } catch (e) {
    // silently ignore — feature may not be configured
  }
}

const fetchCpServers = async () => {
  cpServersLoading.value = true
  try {
    const res = await axios.get('/api/cyberpanel/servers')
    cpServers.value = res.data.servers || []
    // 预选默认可用的第一个服务器
    const first = cpServers.value.find(s => s.available)
    cpSelectedServer.value = first ? first.id : null
  } catch (e) {
    cpServers.value = []
  } finally {
    cpServersLoading.value = false
  }
}

const openCpHosting = (domain) => {
  cpModalDomain.value = domain
  cpFormError.value = ''
  cpCredentials.value = null
  showCpModal.value = true
  // 如果还没有账号，加载服务器列表
  if (!cpAccountByDomain.value[domain.id]) {
    fetchCpServers()
  }
}

const createCpAccount = async () => {
  cpSubmitting.value = true
  cpFormError.value = ''
  try {
    await axios.post('/api/cyberpanel/accounts', {
      domain_id: cpModalDomain.value.id,
      server_id: cpSelectedServer.value || undefined,
    })
    toast.success(t('domains.cpHostingCreated'))
    closeCpModal()
    await fetchCpAccounts()
  } catch (e) {
    cpFormError.value = e.response?.data?.error || 'Failed'
  } finally {
    cpSubmitting.value = false
  }
}

const cpFormLogin = (username, password, loginUrl) => {
  // 打开命名窗口，先 POST 到 /api/loginAPI（免 CSRF）建立 session cookie，
  // 再导航到 /dashboard/，浏览器会携带已设置的 cookie
  const winName = 'cpanel_' + Date.now()
  const cpWindow = window.open('about:blank', winName)
  const form = document.createElement('form')
  form.method = 'POST'
  form.action = `${loginUrl}/api/loginAPI`
  form.target = winName
  ;[['username', username], ['password', password]].forEach(([name, value]) => {
    const input = document.createElement('input')
    input.type = 'hidden'
    input.name = name
    input.value = value
    form.appendChild(input)
  })
  document.body.appendChild(form)
  form.submit()
  document.body.removeChild(form)
  // 等待 loginAPI 响应后（cookie 已写入浏览器），跳转到面板
  setTimeout(() => {
    if (cpWindow && !cpWindow.closed) {
      cpWindow.location.href = `${loginUrl}/dashboard/`
    }
  }, 1500)
}

const fetchCpCredentials = async (acc) => {
  if (cpCredentials.value) {
    // 已加载，仅切换显示/隐藏
    showCpPassword.value = !showCpPassword.value
    return
  }
  cpCredentialsLoading.value = true
  try {
    const res = await axios.get(`/api/cyberpanel/accounts/${acc.id}/autologin`)
    const { username, password, login_url } = res.data
    cpCredentials.value = { cp_username: username, cp_password: password, login_url }
    showCpPassword.value = true
  } catch (e) {
    toast.error(e.response?.data?.error || 'Failed to fetch credentials')
  } finally {
    cpCredentialsLoading.value = false
  }
}

const openCpPanel = async (acc) => {
  cpCredentialsLoading.value = true
  try {
    // 若已缓存凭据直接复用，否则请求
    let creds = cpCredentials.value
    if (!creds) {
      const res = await axios.get(`/api/cyberpanel/accounts/${acc.id}/autologin`)
      const { username, password, login_url } = res.data
      creds = { cp_username: username, cp_password: password, login_url }
      cpCredentials.value = creds
      showCpPassword.value = true
    }
    cpFormLogin(creds.cp_username, creds.cp_password, creds.login_url)
  } catch (e) {
    toast.error(e.response?.data?.error || 'Failed to auto-login')
  } finally {
    cpCredentialsLoading.value = false
  }
}

const copyText = (text) => {
  navigator.clipboard.writeText(text).then(() => {
    toast.success(t('common.copied') || 'Copied!')
  })
}

const confirmDeleteCpAccount = () => {
  showCpDeleteConfirm.value = true
}

const deleteCpAccount = async () => {
  const acc = cpAccountByDomain.value[cpModalDomain.value?.id]
  if (!acc) return
  cpSubmitting.value = true
  try {
    await axios.delete(`/api/cyberpanel/accounts/${acc.id}`)
    toast.success(t('domains.cpHostingDeleted'))
    showCpDeleteConfirm.value = false
    closeCpModal()
    await fetchCpAccounts()
  } catch (e) {
    toast.error(e.response?.data?.error || 'Failed')
  } finally {
    cpSubmitting.value = false
  }
}

// Watch renewYears changes to reset coupon
watch(renewYears, () => {
  // Reset coupon state when years change
  renewCouponApplied.value = false
  renewCouponError.value = ''
  renewPriceData.value = null
})

// Watch renewIsLifetime changes to reset coupon
watch(renewIsLifetime, () => {
  // Reset coupon state when lifetime toggle changes
  renewCouponApplied.value = false
  renewCouponError.value = ''
  renewPriceData.value = null
})

onMounted(async () => {
  await fetchDomains()
  await fetchCpAccounts()
})

const fetchDomains = async () => {
  loading.value = true
  try {
    const response = await axios.get('/api/domains')
    domains.value = response.data.domains
  } catch (error) {
    console.error('Failed to fetch domains:', error)
  } finally {
    loading.value = false
  }
}

// Selection is kept in the URL (?d=<id>) so reloads and bookmarks restore it.
const activeDomain = computed(() => {
  const list = domains.value
  if (!list.length) return null
  const q = Number(route.query.d)
  return list.find((d) => d.id === q) || list[0]
})

const selectDomain = (domain) => {
  if (String(domain.id) !== String(route.query.d || '')) {
    router.replace({ query: { ...route.query, d: domain.id } })
  }
}

const parseNameservers = (domain) => {
  if (domain?.nameservers) {
    try {
      const ns = JSON.parse(domain.nameservers)
      if (Array.isArray(ns) && ns.length > 0) return ns.slice()
    } catch (e) {
      // fall through to blanks
    }
  }
  return ['', '']
}

// Reset the inline DNS-mode editor whenever the selection (or its saved state) changes.
watch(
  activeDomain,
  (d, prev) => {
    if (!d) return
    if (String(d.id) !== String(route.query.d || '')) {
      router.replace({ query: { ...route.query, d: d.id } })
    }
    if (!prev || prev.id !== d.id || prev.use_default_nameservers !== d.use_default_nameservers) {
      segOverride.value = null
      inlineNS.value = parseNameservers(d)
    }
  },
  { immediate: true }
)

const isCustomMode = computed(() => {
  const d = activeDomain.value
  if (!d) return false
  if (segOverride.value) return segOverride.value === 'custom'
  return !d.use_default_nameservers
})

const setMode = (mode) => {
  const d = activeDomain.value
  if (!d) return
  if (mode === 'custom') {
    segOverride.value = 'custom'
    inlineNS.value = parseNameservers(d)
  } else if (d.use_default_nameservers) {
    segOverride.value = null
  } else if (confirm(t('app2.domains.confirmDefaultNS', { domain: d.full_domain }))) {
    switchToDefaultNS(d)
  }
}

const switchToDefaultNS = async (domain) => {
  nsSwitching.value = true
  try {
    await axios.put(`/api/domains/${domain.id}/nameservers`, {
      nameservers: ['ns1.nodelook.com', 'ns2.nodelook.com']
    })
    toast.success('Nameservers updated successfully')
    segOverride.value = null
    await fetchDomains()
  } catch (error) {
    toast.error(error.response?.data?.error || 'Failed to update nameservers')
  } finally {
    nsSwitching.value = false
  }
}

const saveInlineNS = async () => {
  const d = activeDomain.value
  if (!d) return
  const nsToSave = inlineNS.value.filter((ns) => ns.trim() !== '')
  if (nsToSave.length === 0) {
    toast.warning('Please add at least one nameserver')
    return
  }
  nsSwitching.value = true
  try {
    await axios.put(`/api/domains/${d.id}/nameservers`, { nameservers: nsToSave })
    toast.success('Nameservers updated successfully')
    await fetchDomains()
  } catch (error) {
    toast.error(error.response?.data?.error || 'Failed to update nameservers')
  } finally {
    nsSwitching.value = false
  }
}

const getStatusTone = (status) => {
  switch (status) {
    case 'active':
      return 'ok'
    case 'expired':
    case 'abuse':
      return 'danger'
    case 'suspended':
      return 'warn'
    case 'pending':
      return 'info'
    default:
      return 'muted'
  }
}

const statusLabel = (status) => (te(`uiDomains.status.${status}`) ? t(`uiDomains.status.${status}`) : status)

const statusTextClass = (status) =>
  ({
    active: 'text-y-faint',
    expired: 'text-y-danger-text',
    abuse: 'text-y-danger-text',
    suspended: 'text-y-warn',
    pending: 'text-y-info',
  })[status] || 'text-y-faint'

// The glowing dot marks names that are live: custom NS, or synced/known to have records.
const dotActive = (domain) => {
  if (domain.status !== 'active') return false
  if (!domain.use_default_nameservers) return true
  const n = recordCounts.value[domain.id]
  if (n !== undefined) return n > 0
  return !!domain.dns_synced
}

const listStatus = (domain) => {
  if (domain.status !== 'active') return statusLabel(domain.status)
  if (!domain.use_default_nameservers) return t('app2.domains.segCustom')
  const n = recordCounts.value[domain.id]
  if (n === 0) return t('uiDomains.noRecordsShort')
  return statusLabel('active')
}

const formatDate = (dateString) => {
  return formatDateUtil(dateString)
}

const getDaysUntilExpiry = (expiryDate) => {
  return daysUntilExpiry(expiryDate)
}

const getDaysUntilDeletion = (firstFailedAt) => {
  if (!firstFailedAt) return null
  const now = new Date()
  const failedDate = new Date(firstFailedAt)
  const daysSinceFailure = Math.floor((now - failedDate) / (1000 * 60 * 60 * 24))
  return 30 - daysSinceFailure
}

const isUsingDefaultNS = (domain) => {
  return domain.use_default_nameservers
}

// Nameserver Management (modal)
const openModifyNS = (domain) => {
  selectedDomain.value = domain

  // Parse existing nameservers from domain
  if (domain.nameservers) {
    try {
      const ns = JSON.parse(domain.nameservers)
      nameservers.value = ns.length > 0 ? ns : ['', '']
      useCustomNS.value = !domain.use_default_nameservers
    } catch (e) {
      nameservers.value = ['', '']
      useCustomNS.value = true
    }
  } else {
    nameservers.value = ['', '']
    useCustomNS.value = true
  }

  showNSModal.value = true
}

const addNameserver = () => {
  nameservers.value.push('')
}

const removeNameserver = (index) => {
  nameservers.value.splice(index, 1)
}

const saveNameservers = async () => {
  let nsToSave = []

  if (useCustomNS.value) {
    // Use custom nameservers
    nsToSave = nameservers.value.filter(ns => ns.trim() !== '')

    if (nsToSave.length === 0) {
      toast.warning('Please add at least one nameserver')
      return
    }
  } else {
    // Use default nameservers
    nsToSave = ['ns1.nodelook.com', 'ns2.nodelook.com']
  }

  submitting.value = true
  try {
    await axios.put(`/api/domains/${selectedDomain.value.id}/nameservers`, {
      nameservers: nsToSave
    })
    toast.success('Nameservers updated successfully')
    closeNSModal()
    await fetchDomains()
  } catch (error) {
    toast.error(error.response?.data?.error || 'Failed to update nameservers')
  } finally {
    submitting.value = false
  }
}

const closeNSModal = () => {
  showNSModal.value = false
  selectedDomain.value = null
  nameservers.value = ['', '']
  useCustomNS.value = false
}

// Renew Domain
const openRenew = (domain) => {
  selectedDomain.value = domain
  renewYears.value = 1
  renewIsLifetime.value = false
  showRenewModal.value = true
}

const calculateNewExpiry = (currentExpiry, years) => {
  if (renewIsLifetime.value) {
    return t('domains.permanentDomain')
  }
  const newDate = addYears(currentExpiry, years)
  return formatDate(newDate)
}

const calculateRenewPrice = () => {
  if (!selectedDomain.value?.root_domain) return 0
  if (renewIsLifetime.value) {
    return selectedDomain.value.root_domain.lifetime_price || 0
  }
  return (selectedDomain.value.root_domain.price_per_year || 0) * renewYears.value
}

const renewDomain = async () => {
  submitting.value = true
  try {
    const payload = {
      years: renewIsLifetime.value ? 0 : renewYears.value,
      is_lifetime: renewIsLifetime.value
    }

    // 添加优惠券参数（如果有）
    if (renewCouponCode.value && renewCouponCode.value.trim() !== '') {
      payload.coupon_code = renewCouponCode.value.trim()
    }

    const response = await axios.post(`/api/domains/${selectedDomain.value.id}/renew`, payload)

    // 如果返回了订单ID，说明创建了订单（付费域名）
    if (response.data.order_id) {
      const orderId = response.data.order_id
      const finalPrice = response.data.final_price || 0

      // 如果后端已经处理为免费订单（requires_payment: false），直接跳转成功页
      // 后端在检测到 finalPrice < 0.01 时会自动完成续费
      if (!response.data.requires_payment || finalPrice < 0.01) {
        window.location.href = `/payment/success?order_id=${orderId}`
        return
      }

      // 需要支付，发起支付流程
      const paymentResponse = await axios.post(`/api/payments/${orderId}/initiate`)
      const redirectURL = paymentResponse.data.redirect_url
      // 跳转到支付页面
      window.location.href = redirectURL
    } else {
      // 免费域名直接续费成功（没有创建订单）
      if (renewIsLifetime.value) {
        toast.success('Domain renewed for lifetime')
      } else {
        toast.success(`Domain renewed for ${renewYears.value} year(s)`)
      }
      closeRenewModal()
      await fetchDomains()
    }
  } catch (error) {
    toast.error(error.response?.data?.error || t('domains.renewFailed'))
  } finally {
    submitting.value = false
  }
}

const closeRenewModal = () => {
  showRenewModal.value = false
  selectedDomain.value = null
  renewYears.value = 1
  renewIsLifetime.value = false
  renewCouponCode.value = ''
  renewCouponApplied.value = false
  renewCouponError.value = ''
  renewCouponApplying.value = false
  renewPriceData.value = null
}

// 辅助函数：将错误消息中的 RFC3339 时间转换为本地时间
const convertTimeInErrorMessage = (message) => {
  if (!message) return message

  // 匹配 RFC3339 格式的时间字符串，如 "2026-02-17T00:00:00Z" 或 "2026-02-17T00:00:00+08:00"
  const rfc3339Pattern = /(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))/g

  return message.replace(rfc3339Pattern, (match) => {
    try {
      const date = new Date(match)
      return date.toLocaleString()
    } catch (e) {
      return match
    }
  })
}

const applyRenewCoupon = async () => {
  if (!renewCouponCode.value || !selectedDomain.value) return

  renewCouponApplying.value = true
  renewCouponError.value = ''
  renewCouponApplied.value = false

  try {
    const response = await axios.post('/api/orders/calculate', {
      root_domain_id: selectedDomain.value.root_domain_id,
      years: renewIsLifetime.value ? 0 : renewYears.value,
      is_lifetime: renewIsLifetime.value,
      coupon_code: renewCouponCode.value
    })

    renewPriceData.value = response.data

    if (response.data.coupon_applied) {
      renewCouponApplied.value = true
      toast.success(t('coupon.applySuccess'))
    } else if (response.data.coupon_error) {
      // 使用后端返回的详细错误信息，并转换时间为本地时间
      renewCouponError.value = convertTimeInErrorMessage(response.data.coupon_error)
    } else {
      renewCouponError.value = t('domains.cannotApplyToRenewal')
    }
  } catch (error) {
    const errorMsg = error.response?.data?.error || t('coupon.applyFailed')
    renewCouponError.value = convertTimeInErrorMessage(errorMsg)
    renewPriceData.value = null
  } finally {
    renewCouponApplying.value = false
  }
}

// Transfer Domain
const openTransfer = (domain) => {
  selectedDomain.value = domain
  transferTarget.value = ''
  showTransferModal.value = true
}

const transferDomain = async () => {
  if (!transferTarget.value.trim()) {
    toast.warning(t('domains.transferRecipientRequired'))
    return
  }

  if (!confirm(t('domains.confirmTransfer', { domain: selectedDomain.value.full_domain, target: transferTarget.value }))) {
    return
  }

  submitting.value = true
  try {
    await axios.post(`/api/domains/${selectedDomain.value.id}/transfer`, {
      target: transferTarget.value
    })
    toast.success(t('domains.transferSuccess'))
    closeTransferModal()
    await fetchDomains()
  } catch (error) {
    toast.error(error.response?.data?.error || t('domains.transferFailed'))
  } finally {
    submitting.value = false
  }
}

const closeTransferModal = () => {
  showTransferModal.value = false
  selectedDomain.value = null
  transferTarget.value = ''
}

// Suspended Info
const openSuspendedInfo = (domain) => {
  suspendedInfoDomain.value = domain
  showSuspendedInfoModal.value = true
}

// Delete Domain
const confirmDelete = (domain) => {
  deleteTargetDomain.value = domain
  deleteConfirmInput.value = ''
  showDeleteModal.value = true
}

const executeDelete = async () => {
  if (deleting.value) return
  if (deleteConfirmInput.value !== deleteTargetDomain.value?.full_domain) return
  deleting.value = true
  try {
    await axios.delete(`/api/domains/${deleteTargetDomain.value.id}`)
    showDeleteModal.value = false
    toast.success(t('domains.deleteSuccess'))
    await fetchDomains()
  } catch (error) {
    toast.error(error.response?.data?.error || t('domains.deleteFailed'))
  } finally {
    deleting.value = false
  }
}

// FOSSBilling Sync
const openSyncModal = () => {
  // 使用配置中的默认 URL（如果有）
  syncForm.value = {
    fossbilling_url: siteConfig.fossbilling?.url || '',
    fossbilling_api_key: ''
  }
  syncResult.value = null
  showSyncModal.value = true
}

const syncFromFOSSBilling = async () => {
  // 验证必填字段
  if (!syncForm.value.fossbilling_url && !siteConfig.fossbilling?.url) {
    toast.warning('Please enter FOSSBilling server URL')
    return
  }

  if (!syncForm.value.fossbilling_api_key) {
    toast.warning('Please enter FOSSBilling API Key')
    return
  }

  syncInProgress.value = true
  syncResult.value = null

  try {
    const response = await axios.post('/api/user/sync-from-fossbilling', syncForm.value)
    syncResult.value = response.data

    if (response.data.synced_count > 0) {
      toast.success(`Successfully synced ${response.data.synced_count} domain(s)`)
      // Refresh domain list after sync
      await fetchDomains()
    } else {
      toast.info('No new domains to sync')
    }
  } catch (error) {
    toast.error(error.response?.data?.error || 'Failed to sync from FOSSBilling')
    syncResult.value = {
      message: 'Sync failed',
      error_count: 1,
      synced_count: 0,
      existing_count: 0,
      skipped_count: 0,
      details: [error.response?.data?.error || 'An error occurred during sync']
    }
  } finally {
    syncInProgress.value = false
  }
}

const closeSyncModal = () => {
  if (syncInProgress.value) {
    return
  }
  showSyncModal.value = false
  syncForm.value = {
    fossbilling_url: '',
    fossbilling_api_key: ''
  }
  syncResult.value = null
}

// Health Details
const viewHealthDetails = (domain) => {
  selectedDomain.value = domain
  showHealthDetailsModal.value = true
}

const closeHealthDetailsModal = () => {
  showHealthDetailsModal.value = false
  selectedDomain.value = null
}

// Scan Details
const viewScanDetails = async (domain) => {
  selectedDomain.value = domain
  showScanDetailsModal.value = true
  scanPage.value = 1
  await fetchScanRecords()
}

const fetchScanRecords = async () => {
  if (!selectedDomain.value) return

  scanLoading.value = true
  try {
    const response = await axios.get(`/api/domain-scans/${selectedDomain.value.id}`, {
      params: {
        page: scanPage.value,
        page_size: scanPageSize.value
      }
    })
    scanRecords.value = response.data.scans || []
    scanTotalPages.value = response.data.total_pages || 1
  } catch (error) {
    toast.error('Failed to load scan records')
    scanRecords.value = []
  } finally {
    scanLoading.value = false
  }
}

const changeScanPage = async (page) => {
  if (page < 1 || page > scanTotalPages.value) return
  scanPage.value = page
  await fetchScanRecords()
}

const closeScanDetailsModal = () => {
  showScanDetailsModal.value = false
  selectedDomain.value = null
  scanRecords.value = []
  scanPage.value = 1
  scanTotalPages.value = 1
}

// Badge helper functions for scan status
const getHealthBadgeClass = (status) => {
  switch (status?.toLowerCase()) {
    case 'healthy':
      return 'y-chip-mint'
    case 'degraded':
      return 'y-chip-warn'
    case 'down':
      return 'y-chip-danger'
    default:
      return 'y-chip'
  }
}

const getSafeBrowsingBadgeClass = (status) => {
  switch (status?.toLowerCase()) {
    case 'safe':
      return 'y-chip-mint'
    case 'unsafe':
      return 'y-chip-danger'
    default:
      return 'y-chip'
  }
}

const getVirusTotalBadgeClass = (status) => {
  switch (status?.toLowerCase()) {
    case 'clean':
      return 'y-chip-mint'
    case 'malicious':
      return 'y-chip-danger'
    case 'suspicious':
      return 'y-chip-warn'
    default:
      return 'y-chip'
  }
}

const getUptimeClass = (percentage) => {
  if (!percentage && percentage !== 0) return 'text-y-faint'
  if (percentage >= 99) return 'text-y-mint-text'
  if (percentage >= 95) return 'text-y-text'
  if (percentage >= 90) return 'text-y-warn'
  return 'text-y-danger-text'
}

const getScanStatusBadgeClass = (status) => {
  switch (status?.toLowerCase()) {
    case 'completed':
      return 'y-chip-mint'
    case 'failed':
    case 'threat_detected':
      return 'y-chip-danger'
    case 'quota_exceeded':
      return 'y-chip-warn'
    default:
      return 'y-chip'
  }
}

const getStatusBadgeClass = (status) => {
  switch (status?.toLowerCase()) {
    case 'ok':
    case 'valid':
      return 'y-chip-mint'
    case 'error':
    case 'invalid':
      return 'y-chip-danger'
    default:
      return 'y-chip'
  }
}

const visibleScanPages = computed(() => {
  const pages = []
  const total = scanTotalPages.value
  const current = scanPage.value

  if (total <= 7) {
    for (let i = 1; i <= total; i++) {
      pages.push(i)
    }
  } else {
    pages.push(1)
    if (current > 3) pages.push('...')

    const start = Math.max(2, current - 1)
    const end = Math.min(total - 1, current + 1)

    for (let i = start; i <= end; i++) {
      if (!pages.includes(i)) {
        pages.push(i)
      }
    }

    if (current < total - 2) pages.push('...')
    pages.push(total)
  }

  return pages
})

// Presentation helpers
const authStore = useAuthStore()
const siteName = computed(() => siteConfig.siteName || 'Yunamo')

const domainQuota = computed(() => {
  const q = authStore.user?.domain_quota
  return typeof q === 'number' ? q : null
})
const slotsLeft = computed(() => (domainQuota.value === null ? null : Math.max(0, domainQuota.value - domains.value.length)))
const quotaPercent = computed(() => {
  if (!domainQuota.value) return null
  return Math.min(100, Math.round((domains.value.length / domainQuota.value) * 100))
})

const isRestricted = (domain) => domain.status === 'suspended' || domain.status === 'abuse'
const isExpiringSoon = (domain) => domain.status === 'active' && getDaysUntilExpiry(domain.expires_at) <= 30
const hasDeletionNotice = (domain) => !!domain.first_failed_at && getDaysUntilDeletion(domain.first_failed_at) !== null
const needsAttention = (domain) => domain.status !== 'active' || hasDeletionNotice(domain) || isExpiringSoon(domain)

const expiringCount = computed(() => domains.value.filter(isExpiringSoon).length)
const attentionCount = computed(() => domains.value.filter(needsAttention).length)

const searchQuery = ref('')
const statusFilter = ref('all')

const filterOptions = computed(() => [
  { key: 'all', label: t('uiDomains.filterAll'), count: domains.value.length },
  { key: 'active', label: t('uiDomains.filterActive'), count: domains.value.filter((d) => d.status === 'active').length },
  { key: 'attention', label: t('uiDomains.filterAttention'), count: attentionCount.value },
])

const clearFilters = () => {
  searchQuery.value = ''
  statusFilter.value = 'all'
}

const rowNotices = (domain) => {
  const notices = []
  if (domain.status === 'abuse') {
    notices.push({ key: 'abuse', tone: 'danger', text: t('domains.abuseNotice') })
  }
  if (hasDeletionNotice(domain)) {
    const days = getDaysUntilDeletion(domain.first_failed_at)
    notices.push({
      key: 'deletion',
      tone: days <= 3 ? 'danger' : 'warn',
      text: days <= 0 ? t('domains.pendingDeletionSoonNotice') : t('domains.pendingDeletionNotice', { days }),
    })
  }
  return notices
}

const activeNotices = computed(() => (activeDomain.value ? rowNotices(activeDomain.value) : []))

const rows = computed(() => {
  const q = searchQuery.value.trim().toLowerCase()
  return domains.value
    .filter((d) => {
      if (statusFilter.value === 'active' && d.status !== 'active') return false
      if (statusFilter.value === 'attention' && !needsAttention(d)) return false
      return !q || (d.full_domain || '').toLowerCase().includes(q)
    })
    .map((domain) => ({ domain, notices: rowNotices(domain) }))
})

const menuItems = (domain) => {
  const items = [{ key: 'ns', label: t('domains.modifyNameservers'), icon: Server, action: () => openModifyNS(domain) }]
  if (cpAccountByDomain.value[domain.id]) {
    items.push({ key: 'cp', label: t('domains.cpHostingTitle'), icon: Globe, action: () => openCpHosting(domain) })
  }
  if (domain.scan_summary) {
    items.push(
      { key: 'health', label: t('domains.healthDetails'), icon: Activity, action: () => viewHealthDetails(domain) },
      { key: 'scans', label: t('domains.scanDetails'), icon: ChartColumn, action: () => viewScanDetails(domain) }
    )
  }
  items.push(
    { key: 'transfer', label: t('domains.transferDomainTitle'), icon: ArrowLeftRight, action: () => openTransfer(domain) },
    { key: 'delete', label: t('admin.delete'), icon: Trash2, danger: true, divider: true, action: () => confirmDelete(domain) }
  )
  return items
}

// DaisyUI dropdowns stay open while focus is inside them, so drop focus before acting.
const runMenuItem = (item) => {
  document.activeElement?.blur()
  item.action()
}

const healthLabel = (status) => {
  const key = status?.toLowerCase()
  if (key && te(`uiDomains.health.${key}`)) return t(`uiDomains.health.${key}`)
  return status || t('uiDomains.health.unknown')
}

const healthChecks = computed(() => {
  const s = selectedDomain.value?.scan_summary
  if (!s) return []
  return [
    { key: 'http', icon: Globe, title: t('domains.httpStatus'), desc: t('domains.httpStatusDesc'), value: s.http_status, cls: getStatusBadgeClass(s.http_status) },
    { key: 'dns', icon: Network, title: t('domains.dnsStatus'), desc: t('domains.dnsStatusDesc'), value: s.dns_status, cls: getStatusBadgeClass(s.dns_status) },
    { key: 'ssl', icon: Lock, title: t('domains.sslStatus'), desc: t('domains.sslStatusDesc'), value: s.ssl_status, cls: getStatusBadgeClass(s.ssl_status) },
    { key: 'safe', icon: ShieldCheck, title: t('domains.safeBrowsingStatus'), desc: t('domains.safeBrowsingStatusDesc'), value: s.safe_browsing_status, cls: getSafeBrowsingBadgeClass(s.safe_browsing_status) },
    { key: 'vt', icon: Bug, title: t('domains.virusTotalStatus'), desc: t('domains.virusTotalStatusDesc'), value: s.virustotal_status, cls: getVirusTotalBadgeClass(s.virustotal_status) },
  ]
})

const cpStatusChip = (status) => ({
  active: 'y-chip-mint',
  pending: 'y-chip-info',
  suspended: 'y-chip-warn',
  terminated: 'y-chip-danger',
}[status] || 'y-chip')

const cpStatusLabel = (status) => {
  const key = { active: 'cpHostingActive', pending: 'cpHostingPending', suspended: 'cpHostingSuspended', terminated: 'cpHostingTerminated' }[status]
  return key ? t(`domains.${key}`) : status
}

</script>
