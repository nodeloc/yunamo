<template>
  <div class="drawer lg:drawer-open">
    <input id="console-drawer" v-model="drawerOpen" type="checkbox" class="drawer-toggle" />

    <div class="drawer-content flex min-h-screen flex-col">
      <header class="sticky top-0 z-30 border-b border-y-line bg-y-bg/85 backdrop-blur-md">
        <div class="flex h-14 items-center gap-3 px-4 sm:px-6">
          <label for="console-drawer" class="btn btn-ghost btn-sm btn-square lg:hidden" :aria-label="$t('shell.menu')">
            <Menu :size="20" :stroke-width="1.5" />
          </label>
          <router-link to="/" class="lg:hidden" :aria-label="siteName">
            <YLogo variant="mark" class="h-6 w-6" />
          </router-link>

          <div class="hidden min-w-0 items-center gap-2 font-mono text-xs text-y-faint sm:flex">
            <span>{{ isAdminRoute ? $t('shell.adminArea') : $t('shell.workspace') }}</span>
            <span v-if="currentLabel">/</span>
            <span v-if="currentLabel" class="truncate text-y-muted">{{ currentLabel }}</span>
          </div>

          <div class="ml-auto flex items-center gap-1">
            <LanguageSwitcher />
            <ThemeToggle />
            <router-link to="/" class="btn btn-ghost btn-sm hidden gap-1.5 sm:inline-flex">
              {{ $t('shell.viewSite') }}
              <ArrowUpRight :size="14" :stroke-width="1.5" />
            </router-link>
          </div>
        </div>
      </header>

      <main class="flex-1">
        <slot />
      </main>
    </div>

    <div class="drawer-side z-40">
      <label for="console-drawer" class="drawer-overlay" :aria-label="$t('common.close')"></label>
      <aside class="flex h-full min-h-full w-64 flex-col border-r border-y-line bg-y-surface">
        <div class="flex h-14 items-center border-b border-y-line px-5">
          <router-link to="/" :aria-label="siteName">
            <YLogo class="h-6 w-auto" />
          </router-link>
        </div>

        <nav class="flex-1 space-y-6 overflow-y-auto px-3 py-5">
          <div v-for="group in groups" :key="group.key" class="space-y-1">
            <p class="px-3 pb-1 font-mono text-[11px] uppercase tracking-[0.08em] text-y-faint">{{ group.label }}</p>
            <router-link
              v-for="item in group.items"
              :key="item.to"
              :to="item.to"
              class="group flex items-center gap-3 rounded-sm px-3 py-2 text-sm text-y-muted transition-colors hover:bg-y-surface-2 hover:text-y-text"
              :class="{ 'bg-y-surface-2 !text-y-text': isActive(item) }"
            >
              <component
                :is="item.icon"
                :size="16"
                :stroke-width="1.5"
                :class="isActive(item) ? 'text-y-mint-text' : 'text-y-faint group-hover:text-y-muted'"
              />
              <span class="truncate">{{ item.label }}</span>
            </router-link>
          </div>
        </nav>

        <div class="border-t border-y-line p-3">
          <div class="flex items-center gap-3 rounded-sm px-2 py-2">
            <UserAvatar :src="user?.avatar" :name="user?.username" :size="32" />
            <div class="min-w-0 flex-1">
              <p class="truncate text-sm font-medium text-y-text">{{ user?.username || '—' }}</p>
              <p class="truncate text-xs text-y-faint">{{ user?.email }}</p>
            </div>
            <button type="button" class="btn btn-ghost btn-sm btn-square" :title="$t('nav.logout')" :aria-label="$t('nav.logout')" @click="handleLogout">
              <LogOut :size="16" :stroke-width="1.5" />
            </button>
          </div>
        </div>
      </aside>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import {
  Menu, ArrowUpRight, LogOut, LayoutDashboard, Globe, Receipt, Ticket, Gift, User,
  Gauge, Network, ListTree, Users, ShoppingCart, BadgePercent, Megaphone, FileText,
  Activity, Settings, Flag, HeartHandshake, Handshake,
} from 'lucide-vue-next'
import { useAuthStore } from '../stores/auth'
import { useSiteConfigStore } from '../stores/siteConfig'
import YLogo from '../components/brand/YLogo.vue'
import LanguageSwitcher from '../components/LanguageSwitcher.vue'
import ThemeToggle from '../components/ui/ThemeToggle.vue'
import UserAvatar from '../components/ui/UserAvatar.vue'

const route = useRoute()
const router = useRouter()
const { t } = useI18n()
const authStore = useAuthStore()
const siteConfigStore = useSiteConfigStore()

const drawerOpen = ref(false)
const user = computed(() => authStore.user)
const siteName = computed(() => siteConfigStore.siteName || 'Yunamo')
const isAdminRoute = computed(() => route.path.startsWith('/admin'))

onMounted(() => {
  if (authStore.isAuthenticated && !authStore.user) authStore.fetchProfile()
})

watch(() => route.fullPath, () => {
  drawerOpen.value = false
})

const workspaceItems = computed(() => [
  { to: '/dashboard', label: t('nav.dashboard'), icon: LayoutDashboard },
  { to: '/domains', label: t('nav.domains'), icon: Globe, match: ['/domains'] },
  { to: '/orders', label: t('nav.orders'), icon: Receipt, match: ['/orders', '/checkout'] },
  { to: '/coupons', label: t('nav.coupons'), icon: Ticket },
  { to: '/invitations', label: t('nav.invitations'), icon: Gift },
  { to: '/profile', label: t('nav.profile'), icon: User },
])

const adminItems = computed(() => [
  { to: '/admin', label: t('shell.overview'), icon: Gauge, exact: true },
  { to: '/admin/root-domains', label: t('admin.rootDomains'), icon: Network },
  { to: '/admin/domains', label: t('admin.domains'), icon: ListTree },
  { to: '/admin/users', label: t('admin.users'), icon: Users },
  { to: '/admin/orders', label: t('admin.orders'), icon: ShoppingCart },
  { to: '/admin/coupons', label: t('admin.coupons'), icon: BadgePercent },
  { to: '/admin/announcements', label: t('admin.announcements'), icon: Megaphone },
  { to: '/admin/pages', label: t('admin.pages'), icon: FileText },
  { to: '/admin/abuse-reports', label: t('shell.abuseReports'), icon: Flag },
  { to: '/admin/sponsors', label: t('sponsorAdmin.nav'), icon: HeartHandshake },
  { to: '/admin/partner-applications', label: t('partnerAdmin.nav'), icon: Handshake },
  { to: '/admin/scan-status', label: t('admin.scanStatus'), icon: Activity },
  { to: '/admin/settings', label: t('admin.settings'), icon: Settings },
])

const groups = computed(() => {
  const list = [{ key: 'workspace', label: t('shell.workspace'), items: workspaceItems.value }]
  if (user.value?.is_admin) list.push({ key: 'admin', label: t('shell.adminArea'), items: adminItems.value })
  return list
})

const isActive = (item) => {
  if (item.exact) return route.path === item.to
  const prefixes = item.match || [item.to]
  return prefixes.some((p) => route.path === p || route.path.startsWith(p + '/'))
}

const currentLabel = computed(() => {
  const all = [...workspaceItems.value, ...adminItems.value]
  const exact = all.find((i) => route.path === i.to)
  if (exact) return exact.label
  const match = all
    .filter((i) => !i.exact && isActive(i))
    .sort((a, b) => b.to.length - a.to.length)[0]
  return match?.label || ''
})

const handleLogout = () => {
  authStore.logout()
  router.push('/login')
}
</script>
