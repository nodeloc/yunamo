<template>
  <div class="y-container py-14 sm:py-16">
    <div class="max-w-2xl">
      <p class="y-eyebrow">{{ $t('uiPublic.announcements.eyebrow') }}</p>
      <h1 class="y-h1 mt-4">{{ $t('announcement.title') }}</h1>
      <p class="y-lead mt-4">{{ $t('announcement.subtitle') }}</p>
    </div>

    <div class="mt-10">
      <YLoader v-if="loading" :label="$t('common.loading')" />

      <div v-else-if="announcements.length === 0" class="y-panel">
        <EmptyState :title="$t('announcement.noAnnouncements')" :description="$t('announcement.checkLater')" />
      </div>

      <div v-else class="grid gap-3">
        <router-link
          v-for="announcement in announcements"
          :key="announcement.id"
          :to="`/announcements/${announcement.id}`"
          class="y-link-tile flex gap-5 p-5 sm:p-6"
        >
          <span class="y-icon-tile hidden sm:inline-flex">
            <component :is="getTypeIcon(announcement.type)" :size="20" :stroke-width="1.5" />
          </span>
          <div class="min-w-0 flex-1">
            <div class="flex flex-wrap items-center gap-2">
              <span :class="getTypeBadgeClass(announcement.type)">
                <component :is="getTypeIcon(announcement.type)" :size="12" :stroke-width="1.75" />
                {{ formatType(announcement.type) }}
              </span>
              <span v-if="announcement.priority > 0" class="y-chip-warn">
                <Star :size="12" :stroke-width="1.75" />
                {{ $t('announcement.priority') }}
              </span>
            </div>
            <h2 class="y-h3 mt-3">{{ announcement.title }}</h2>
            <p class="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-y-faint">
              <span>{{ formatDate(announcement.published_at || announcement.created_at) }}</span>
              <template v-if="announcement.author_name">
                <span aria-hidden="true">·</span>
                <span>{{ $t('uiPublic.announcements.byAuthor', { name: announcement.author_name }) }}</span>
              </template>
              <span aria-hidden="true">·</span>
              <span>{{ $t('uiPublic.announcements.viewsCount', { count: announcement.views || 0 }) }}</span>
            </p>
            <div class="prose prose-sm mt-3 max-w-none line-clamp-3" v-html="formatContent(announcement.content)"></div>
            <span class="mt-4 inline-flex items-center gap-1.5 text-sm font-medium text-y-mint-text">
              {{ $t('uiPublic.announcements.read') }}
              <ArrowRight :size="16" :stroke-width="1.5" />
            </span>
          </div>
        </router-link>
      </div>
    </div>
  </div>
</template>

<script setup>
import { marked } from 'marked'
import DOMPurify from 'dompurify'
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { Megaphone, Wrench, Sparkles, TriangleAlert, Star, ArrowRight } from 'lucide-vue-next'
import axios from '../utils/axios'
import YLoader from '../components/brand/YLoader.vue'
import EmptyState from '../components/ui/EmptyState.vue'

const { t } = useI18n()
const announcements = ref([])
const loading = ref(true)

onMounted(async () => {
  await fetchAnnouncements()
})

const fetchAnnouncements = async () => {
  loading.value = true
  try {
    const response = await axios.get('/api/public/announcements')
    announcements.value = response.data.announcements
  } catch (error) {
    console.error('Failed to fetch announcements:', error)
  } finally {
    loading.value = false
  }
}

const getTypeBadgeClass = (type) => {
  const classes = {
    general: 'y-chip',
    maintenance: 'y-chip-warn',
    update: 'y-chip-mint',
    important: 'y-chip-danger',
  }
  return classes[type] || 'y-chip'
}

const getTypeIcon = (type) => {
  const icons = {
    general: Megaphone,
    maintenance: Wrench,
    update: Sparkles,
    important: TriangleAlert,
  }
  return icons[type] || Megaphone
}

const formatType = (type) => {
  const typeKey = `announcement.${type}`
  return t(typeKey)
}

const formatDate = (dateString) => {
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  })
}

const formatContent = (content) => {
  if (!content) return ''
  // 与详情页一致：Markdown 渲染后再经 DOMPurify 清洗，防止公告内容注入脚本
  return DOMPurify.sanitize(marked.parse(content))
}
</script>
