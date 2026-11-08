<template>
  <div class="y-page">
    <PageHeader :eyebrow="$t('uiUser.profile.eyebrow')" :title="$t('uiUser.profile.title')" :description="$t('uiUser.profile.description')" />

    <div class="grid gap-6 lg:grid-cols-[1.1fr_1fr] lg:items-start">
      <!-- Account -->
      <section class="y-panel">
        <div class="flex items-center gap-4 border-b border-y-line px-5 py-5">
          <UserAvatar :src="user?.avatar" :name="user?.username" :size="48" />
          <div class="min-w-0">
            <p class="truncate text-[17px] font-semibold text-y-text">{{ user?.username || '—' }}</p>
            <p class="truncate text-sm text-y-muted">{{ user?.email || '—' }}</p>
          </div>
        </div>

        <dl class="grid gap-px bg-y-line sm:grid-cols-2">
          <div class="bg-y-surface px-5 py-4">
            <dt class="y-label">{{ $t('uiUser.profile.username') }}</dt>
            <dd class="mt-2 truncate text-[15px] text-y-text">{{ user?.username || '—' }}</dd>
          </div>
          <div class="bg-y-surface px-5 py-4">
            <dt class="y-label">{{ $t('uiUser.profile.email') }}</dt>
            <dd class="mt-2 space-y-1.5">
              <span class="block truncate text-[15px] text-y-text" :title="user?.email">{{ user?.email || '—' }}</span>
              <StatusDot
                v-if="user"
                :tone="user.email_verified ? 'ok' : 'warn'"
                :label="user.email_verified ? $t('uiUser.dashboard.verified') : $t('uiUser.dashboard.notVerified')"
              />
            </dd>
          </div>
          <div class="bg-y-surface px-5 py-4">
            <dt class="y-label">{{ $t('uiUser.profile.level') }}</dt>
            <dd class="mt-2 text-[15px] text-y-text">{{ levelLabel }}</dd>
          </div>
          <div class="bg-y-surface px-5 py-4">
            <dt class="y-label">{{ $t('uiUser.profile.quota') }}</dt>
            <dd class="mt-2 font-mono text-[15px] text-y-text">{{ user?.domain_quota ?? '—' }}</dd>
          </div>
        </dl>

        <div class="space-y-3 border-t border-y-line px-5 py-5">
          <p class="y-label">{{ $t('uiUser.profile.inviteCode') }}</p>
          <div class="flex items-center gap-2">
            <div class="y-inset min-w-0 flex-1 truncate px-4 py-2.5 font-mono text-[15px] text-y-text">{{ user?.invite_code || '—' }}</div>
            <button type="button" class="btn btn-outline gap-1.5" :disabled="!user?.invite_code" @click="copyInviteCode">
              <Copy :size="16" :stroke-width="1.5" />
              {{ $t('uiUser.common.copy') }}
            </button>
          </div>
          <p class="y-field-hint">{{ $t('uiUser.profile.inviteHint') }}</p>
        </div>
      </section>

      <!-- Change password -->
      <section class="y-panel">
        <div class="border-b border-y-line px-5 py-4">
          <h2 class="y-h3">{{ $t('uiUser.profile.passwordTitle') }}</h2>
          <p class="mt-1 text-sm text-y-muted">{{ $t('uiUser.profile.passwordDesc') }}</p>
        </div>

        <form class="space-y-5 px-5 py-5" @submit.prevent="changePassword">
          <label class="y-field">
            <span class="y-field-label">{{ $t('uiUser.profile.currentPassword') }}</span>
            <input
              v-model="passwordForm.currentPassword"
              type="password"
              class="input input-bordered w-full"
              :placeholder="$t('uiUser.profile.currentPasswordPlaceholder')"
              autocomplete="current-password"
              required
            />
          </label>

          <label class="y-field">
            <span class="y-field-label">{{ $t('uiUser.profile.newPassword') }}</span>
            <input
              v-model="passwordForm.newPassword"
              type="password"
              class="input input-bordered w-full"
              :placeholder="$t('uiUser.profile.newPasswordPlaceholder')"
              autocomplete="new-password"
              minlength="6"
              required
            />
            <span class="y-field-hint">{{ $t('uiUser.profile.newPasswordHint') }}</span>
          </label>

          <label class="y-field">
            <span class="y-field-label">{{ $t('uiUser.profile.confirmPassword') }}</span>
            <input
              v-model="passwordForm.confirmPassword"
              type="password"
              class="input input-bordered w-full"
              :placeholder="$t('uiUser.profile.confirmPasswordPlaceholder')"
              autocomplete="new-password"
              minlength="6"
              required
            />
          </label>

          <div class="flex flex-wrap gap-2 pt-1">
            <button type="submit" class="btn btn-primary" :disabled="changingPassword">
              <span v-if="changingPassword" class="loading loading-spinner loading-sm"></span>
              {{ changingPassword ? $t('uiUser.profile.updating') : $t('uiUser.profile.updatePassword') }}
            </button>
            <button type="button" class="btn btn-ghost" @click="resetPasswordForm">
              {{ $t('common.cancel') }}
            </button>
          </div>
        </form>
      </section>
    </div>
  </div>
</template>
<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAuthStore } from '../stores/auth'
import { useToast } from '../composables/useToast'
import axios from '../utils/axios'
import { Copy } from 'lucide-vue-next'
import PageHeader from '../components/ui/PageHeader.vue'
import StatusDot from '../components/ui/StatusDot.vue'
import UserAvatar from '../components/ui/UserAvatar.vue'

const { t, te } = useI18n()
const authStore = useAuthStore()
const user = computed(() => authStore.user)
const toast = useToast()

const levelLabel = computed(() => {
  const level = user.value?.user_level
  if (!level) return '—'
  return te(`home.levelNames.${level}`) ? t(`home.levelNames.${level}`) : level
})

const changingPassword = ref(false)
const passwordForm = reactive({
  currentPassword: '',
  newPassword: '',
  confirmPassword: ''
})

onMounted(async () => {
  if (!authStore.user) {
    await authStore.fetchProfile()
  }
})

const copyInviteCode = () => {
  if (user.value?.invite_code) {
    navigator.clipboard.writeText(user.value.invite_code)
    toast.success(t('user.inviteCodeCopied'))
  }
}

const changePassword = async () => {
  if (passwordForm.newPassword !== passwordForm.confirmPassword) {
    toast.error(t('user.passwordMismatch'))
    return
  }

  if (passwordForm.newPassword.length < 6) {
    toast.error(t('user.passwordTooShort'))
    return
  }

  changingPassword.value = true
  try {
    const res = await axios.put('/api/user/change-password', {
      current_password: passwordForm.currentPassword,
      new_password: passwordForm.newPassword
    })
    // 改密后旧 token 全部失效，换用服务端返回的新 token
    if (res.data?.token) {
      authStore.token = res.data.token
      try { localStorage.setItem('token', res.data.token) } catch (e) { /* ignore */ }
    }
    toast.success(t('user.passwordChangeSuccess'))
    resetPasswordForm()
  } catch (error) {
    toast.error(t('user.passwordChangeFailed') + ': ' + (error.response?.data?.error || error.message))
  } finally {
    changingPassword.value = false
  }
}

const resetPasswordForm = () => {
  passwordForm.currentPassword = ''
  passwordForm.newPassword = ''
  passwordForm.confirmPassword = ''
}
</script>
