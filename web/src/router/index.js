import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '../stores/auth'

const routes = [
  {
    path: '/',
    name: 'Home',
    component: () => import('../views/Home.vue'),
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('../views/Login.vue'),
    meta: { layout: 'bare' },
  },
  {
    path: '/register',
    name: 'Register',
    component: () => import('../views/Register.vue'),
    meta: { layout: 'bare' },
  },
  {
    path: '/forgot-password',
    name: 'ForgotPassword',
    component: () => import('../views/ForgotPassword.vue'),
    meta: { layout: 'bare' },
  },
  {
    path: '/reset-password',
    name: 'ResetPassword',
    component: () => import('../views/ResetPassword.vue'),
    meta: { layout: 'bare' },
  },
  {
    path: '/verify-email',
    name: 'VerifyEmail',
    component: () => import('../views/VerifyEmail.vue'),
    meta: { layout: 'bare' },
  },
  {
    path: '/dashboard',
    name: 'Dashboard',
    component: () => import('../views/Dashboard.vue'),
    meta: { requiresAuth: true, layout: 'app' },
  },
  {
    path: '/domains',
    name: 'Domains',
    component: () => import('../views/Domains.vue'),
    meta: { requiresAuth: true, layout: 'app' },
  },
  {
    path: '/profile',
    name: 'Profile',
    component: () => import('../views/Profile.vue'),
    meta: { requiresAuth: true, layout: 'app' },
  },
  {
    path: '/domains/:domainId/dns',
    name: 'DNSManagement',
    component: () => import('../views/DNSManagement.vue'),
    meta: { requiresAuth: true, layout: 'app' },
  },
  {
    path: '/coupons',
    name: 'Coupons',
    component: () => import('../views/Coupons.vue'),
    meta: { requiresAuth: true, layout: 'app' },
  },
  {
    path: '/admin',
    name: 'Admin',
    component: () => import('../views/AdminDashboard.vue'),
    meta: { requiresAuth: true, requiresAdmin: true, layout: 'console' },
  },
  {
    path: '/admin/coupons',
    name: 'AdminCoupons',
    component: () => import('../views/AdminCoupons.vue'),
    meta: { requiresAuth: true, requiresAdmin: true, layout: 'console' },
  },
  {
    path: '/invitations',
    name: 'Invitations',
    component: () => import('../views/Invitations.vue'),
    meta: { requiresAuth: true, layout: 'app' },
  },
  {
    path: '/announcements',
    name: 'Announcements',
    component: () => import('../views/Announcements.vue'),
  },
  {
    path: '/announcements/:id',
    name: 'AnnouncementDetail',
    component: () => import('../views/AnnouncementDetail.vue'),
  },
  {
    path: '/pending-domains',
    name: 'PendingDomains',
    component: () => import('../views/PendingDomains.vue'),
  },
  {
    path: '/admin/announcements',
    name: 'AdminAnnouncements',
    component: () => import('../views/AdminAnnouncements.vue'),
    meta: { requiresAuth: true, requiresAdmin: true, layout: 'console' },
  },
  {
    path: '/admin/root-domains',
    name: 'AdminRootDomains',
    component: () => import('../views/AdminRootDomains.vue'),
    meta: { requiresAuth: true, requiresAdmin: true, layout: 'console' },
  },
  {
    path: '/admin/root-domains/:id/domains',
    name: 'AdminRootDomainDomains',
    component: () => import('../views/AdminRootDomainDomains.vue'),
    meta: { requiresAuth: true, requiresAdmin: true, layout: 'console' },
  },
  {
    path: '/domain-health',
    name: 'DomainHealth',
    component: () => import('../views/DomainHealth.vue'),
  },
  {
    path: '/checkout',
    name: 'Checkout',
    component: () => import('../views/DomainCheckout.vue'),
    meta: { requiresAuth: true, layout: 'app' },
  },
  {
    path: '/orders',
    name: 'Orders',
    component: () => import('../views/OrderList.vue'),
    meta: { requiresAuth: true, layout: 'app' },
  },
  {
    path: '/auth/callback',
    name: 'AuthCallback',
    component: () => import('../views/AuthCallback.vue'),
  },
  {
    path: '/payment/success',
    name: 'PaymentSuccess',
    component: () => import('../views/PaymentCallback.vue'),
  },
  {
    path: '/payment/failure',
    name: 'PaymentFailure',
    component: () => import('../views/PaymentCallback.vue'),
  },
  {
    path: '/admin/pages',
    name: 'AdminPages',
    component: () => import('../views/AdminPages.vue'),
    meta: { requiresAuth: true, requiresAdmin: true, layout: 'console' },
  },
  {
    path: '/admin/users',
    name: 'AdminUsers',
    component: () => import('../views/AdminUsers.vue'),
    meta: { requiresAuth: true, requiresAdmin: true, layout: 'console' },
  },
  {
    path: '/admin/orders',
    name: 'AdminOrders',
    component: () => import('../views/AdminOrders.vue'),
    meta: { requiresAuth: true, requiresAdmin: true, layout: 'console' },
  },
  {
    path: '/admin/settings',
    name: 'AdminSettings',
    component: () => import('../views/AdminSettings.vue'),
    meta: { requiresAuth: true, requiresAdmin: true, layout: 'console' },
  },
  {
    path: '/admin/domains',
    name: 'AdminDomains',
    component: () => import('../views/AdminDomains.vue'),
    meta: { requiresAuth: true, requiresAdmin: true, layout: 'console' },
  },
  {
    path: '/admin/pending-domains',
    name: 'AdminPendingDomains',
    component: () => import('../views/AdminPendingDomains.vue'),
    meta: { requiresAuth: true, requiresAdmin: true, layout: 'console' },
  },
  {
    path: '/admin/scan-status',
    name: 'AdminScanStatus',
    component: () => import('../views/AdminScanStatus.vue'),
    meta: { requiresAuth: true, requiresAdmin: true, layout: 'console' },
  },
  {
    path: '/status',
    name: 'Status',
    component: () => import('../views/Status.vue'),
  },
  {
    path: '/sponsor',
    name: 'Sponsor',
    component: () => import('../views/Sponsor.vue'),
  },
  {
    path: '/acceptable-use',
    name: 'AcceptableUse',
    component: () => import('../views/AcceptableUse.vue'),
  },
  {
    path: '/report',
    name: 'ReportAbuse',
    component: () => import('../views/ReportAbuse.vue'),
  },
  {
    path: '/docs',
    redirect: '/pages/documentation',
  },
  {
    path: '/admin/abuse-reports',
    name: 'AdminAbuseReports',
    component: () => import('../views/AdminAbuseReports.vue'),
    meta: { requiresAuth: true, requiresAdmin: true, layout: 'console' },
  },
  {
    path: '/admin/sponsors',
    name: 'AdminSponsors',
    component: () => import('../views/AdminSponsors.vue'),
    meta: { requiresAuth: true, requiresAdmin: true, layout: 'console' },
  },
  {
    path: '/admin/partner-applications',
    name: 'AdminPartnerApplications',
    component: () => import('../views/AdminPartnerApplications.vue'),
    meta: { requiresAuth: true, requiresAdmin: true, layout: 'console' },
  },
  {
    path: '/pages/:slug',
    name: 'PageView',
    component: () => import('../views/PageView.vue'),
    meta: { layout: 'docs' },
  },
  {
    path: '/whois/:domain',
    name: 'WhoisDetail',
    component: () => import('../views/WhoisDetail.vue'),
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'NotFound',
    component: () => import('../views/NotFound.vue'),
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior(to, from, savedPosition) {
    return savedPosition || { top: 0 }
  },
})

// 路由守卫
router.beforeEach(async (to, from, next) => {
  const authStore = useAuthStore()

  // 如果需要认证但未登录，跳转到登录页
  if (to.meta.requiresAuth && !authStore.isAuthenticated) {
    next('/login')
    return
  }

  // 如果已登录但访问登录/注册页，跳转到首页
  if ((to.name === 'Login' || to.name === 'Register') && authStore.isAuthenticated) {
    next('/dashboard')
    return
  }

  // 如果需要管理员权限
  if (to.meta.requiresAdmin) {
    // 确保已加载用户信息
    if (!authStore.user) {
      await authStore.fetchProfile()
    }

    // 检查是否为管理员
    if (!authStore.isAdmin) {
      // 显示错误提示并重定向到首页
      alert('Access denied: Admin privileges required')
      next('/dashboard')
      return
    }
  }

  next()
})

export default router
