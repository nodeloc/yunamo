import { defineStore } from 'pinia'
import axios from '../utils/axios'

export const useSiteConfigStore = defineStore('siteConfig', {
  state: () => ({
    siteName: '',
    siteDescription: '',
    oauth: {},
    allowPasswordRegister: true,
    currencySymbol: 'NL',
    loaded: false,
  }),

  actions: {
    async fetch() {
      try {
        const res = await axios.get('/api/public/site-config')
        this.siteName = res.data.site_name || ''
        this.siteDescription = res.data.site_description || ''
        this.oauth = res.data.oauth || {}
        this.allowPasswordRegister = res.data.allow_password_register !== false
        this.currencySymbol = res.data.currency_symbol || 'NL'
        this.loaded = true
      } catch (err) {
        console.error('Failed to fetch site config:', err)
      }
    },
  },
})
