<template>
  <div class="y-page">
    <PageHeader
      :eyebrow="$t('shell.adminArea')"
      :title="$t('uiAdmin1.dashboard.title')"
      :description="$t('admin.subtitle', { siteName })"
    />

    <section class="y-panel grid grid-cols-1 divide-y divide-y-line sm:grid-cols-3 sm:divide-x sm:divide-y-0">
      <div v-for="stat in statCells" :key="stat.key" class="space-y-2 p-5">
        <div class="flex items-center justify-between gap-3">
          <p class="y-label">{{ stat.label }}</p>
          <component :is="stat.icon" :size="16" :stroke-width="1.5" class="text-y-faint" />
        </div>
        <p class="font-mono text-3xl font-medium tracking-tight text-y-text">{{ stat.value }}</p>
        <p class="text-xs text-y-faint">{{ stat.hint }}</p>
      </div>
    </section>

    <section class="space-y-3">
      <h2 class="y-label">{{ $t('uiAdmin1.dashboard.sections') }}</h2>
      <div class="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <router-link
          v-for="item in sections"
          :key="item.to"
          :to="item.to"
          class="y-link-tile group flex items-center gap-3 p-4"
        >
          <span class="y-icon-tile h-9 w-9">
            <component :is="item.icon" :size="18" :stroke-width="1.5" />
          </span>
          <span class="min-w-0 flex-1">
            <span class="block truncate text-sm font-medium text-y-text">{{ item.title }}</span>
            <span class="mt-0.5 block truncate text-xs text-y-muted">{{ item.description }}</span>
          </span>
          <ChevronRight :size="16" :stroke-width="1.5" class="shrink-0 text-y-faint transition-colors group-hover:text-y-muted" />
        </router-link>
      </div>
    </section>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  Users, Globe, Wallet, ChevronRight, Network, ListTree, ShoppingCart, BadgePercent,
  Megaphone, FileText, Activity, Settings,
} from 'lucide-vue-next'
import axios from '../utils/axios'
import { useSiteConfigStore } from '../stores/siteConfig'
import { useCurrency } from '../composables/useCurrency'
import PageHeader from '../components/ui/PageHeader.vue'

const { t } = useI18n()
const siteConfigStore = useSiteConfigStore()
const { formatPrice } = useCurrency()

const siteName = computed(() => siteConfigStore.siteName || 'Yunamo')

const stats = ref({
  total_users: 0,
  total_domains: 0,
  total_revenue: 0,
})

const statCells = computed(() => [
  { key: 'users', icon: Users, label: t('admin.totalUsers'), value: stats.value.total_users || 0, hint: t('admin.platformUsers') },
  { key: 'domains', icon: Globe, label: t('admin.totalDomains'), value: stats.value.total_domains || 0, hint: t('admin.registeredDomains') },
  { key: 'revenue', icon: Wallet, label: t('admin.totalRevenue'), value: formatPrice(stats.value.total_revenue || 0), hint: t('admin.fromPaidDomains') },
])

const sections = computed(() => [
  { to: '/admin/root-domains', icon: Network, title: t('admin.rootDomains'), description: t('admin.rootDomainsDesc') },
  { to: '/admin/domains', icon: ListTree, title: t('admin.domains'), description: t('admin.domainsDesc') },
  { to: '/admin/users', icon: Users, title: t('admin.users'), description: t('admin.usersDesc') },
  { to: '/admin/orders', icon: ShoppingCart, title: t('admin.orders'), description: t('admin.ordersDesc') },
  { to: '/admin/coupons', icon: BadgePercent, title: t('admin.coupons'), description: t('admin.couponsDesc') },
  { to: '/admin/announcements', icon: Megaphone, title: t('admin.announcements'), description: t('admin.announcementsDesc') },
  { to: '/admin/pages', icon: FileText, title: t('admin.pages'), description: t('admin.pagesDesc') },
  { to: '/admin/scan-status', icon: Activity, title: t('admin.scanStatus'), description: t('admin.scanStatusDesc') },
  { to: '/admin/settings', icon: Settings, title: t('admin.settings'), description: t('admin.settingsDesc') },
])

const fetchStats = async () => {
  try {
    const response = await axios.get('/api/admin/dashboard-stats')
    stats.value = response.data
  } catch (error) {
    console.error('Failed to fetch dashboard stats:', error)
  }
}

onMounted(async () => {
  await fetchStats()
})
</script>
