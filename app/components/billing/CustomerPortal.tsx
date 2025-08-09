'use client';

import React, { useState, useEffect } from 'react';
import { 
  Card, 
  CardContent, 
  CardDescription, 
  CardHeader, 
  CardTitle 
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  CreditCard, 
  Download, 
  Eye, 
  Settings, 
  User, 
  Building2,
  Calendar,
  DollarSign,
  Activity,
  Bell,
  Shield,
  FileText,
  ChevronRight,
  AlertCircle,
  CheckCircle,
  Clock,
  TrendingUp
} from 'lucide-react';
import { formatCurrency, formatDate } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';

// Types
interface CustomerInfo {
  id: string;
  tenantId: string;
  email: string;
  name: string;
  phone?: string;
  taxId?: string;
  billingAddress?: BillingAddress;
  securityClearance: string;
  createdAt: string;
  updatedAt: string;
  status: string;
  accountBalance: number;
  creditLimit?: number;
  currency: string;
  timezone: string;
  language: string;
  activeSubscriptions: number;
  trialSubscriptions: number;
  nextRenewalDate?: string;
}

interface BillingAddress {
  line1: string;
  line2?: string;
  city: string;
  state?: string;
  postalCode: string;
  country: string;
}

interface Subscription {
  id: string;
  tenantId: string;
  customerId: string;
  stripeSubscriptionId: string;
  planId: string;
  status: string;
  currentPeriodStart: string;
  currentPeriodEnd: string;
  unitAmount: number;
  quantity: number;
  currency: string;
  securityClearance: string;
  plan?: SubscriptionPlan;
}

interface SubscriptionPlan {
  id: string;
  name: string;
  description?: string;
  unitAmount: number;
  currency: string;
  interval: string;
  intervalCount: number;
  features: PlanFeature[];
}

interface PlanFeature {
  name: string;
  description?: string;
  enabled: boolean;
  limit?: any;
}

interface Invoice {
  id: string;
  tenantId: string;
  customerId: string;
  invoiceNumber: string;
  invoiceType: string;
  status: string;
  invoiceDate: string;
  dueDate: string;
  currency: string;
  subtotalAmount: number;
  taxAmount: number;
  discountAmount: number;
  totalAmount: number;
  amountPaid: number;
  amountDue: number;
  pdfGenerated: boolean;
  emailSent: boolean;
}

interface PaymentMethod {
  id: string;
  tenantId: string;
  customerId: string;
  type: string;
  status: string;
  isDefault: boolean;
  cardBrand?: string;
  cardLast4?: string;
  cardExpMonth?: number;
  cardExpYear?: number;
  billingAddress?: BillingAddress;
  createdAt: string;
  updatedAt: string;
}

interface UsageResponse {
  subscriptionId: string;
  period: {
    startDate: string;
    endDate: string;
  };
  usageItems: UsageItem[];
  totalUsage: number;
  includedUsage: number;
  overageUsage: number;
  overageAmount: number;
  currency: string;
}

interface UsageItem {
  metricName: string;
  metricUnit: string;
  quantity: number;
  unitPrice: number;
  amount: number;
  includedQuantity: number;
  overageQuantity: number;
}

// Main Customer Portal Component
export default function CustomerPortal() {
  const [activeTab, setActiveTab] = useState('overview');
  const [customer, setCustomer] = useState<CustomerInfo | null>(null);
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
  const [invoices, setInvoices] = useState<Invoice[]>([]);
  const [paymentMethods, setPaymentMethods] = useState<PaymentMethod[]>([]);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    loadPortalData();
  }, []);

  const loadPortalData = async () => {
    try {
      setLoading(true);
      await Promise.all([
        loadCustomerInfo(),
        loadSubscriptions(),
        loadInvoices(),
        loadPaymentMethods()
      ]);
    } catch (error) {
      console.error('Failed to load portal data:', error);
      toast({
        title: 'Error',
        description: 'Failed to load account data. Please try again.',
        variant: 'destructive'
      });
    } finally {
      setLoading(false);
    }
  };

  const loadCustomerInfo = async () => {
    const response = await fetch('/api/v1/portal/customer', {
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`,
        'X-Customer-ID': getCurrentCustomerId()
      }
    });
    
    if (response.ok) {
      const data = await response.json();
      setCustomer(data);
    }
  };

  const loadSubscriptions = async () => {
    const response = await fetch('/api/v1/portal/subscriptions', {
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`,
        'X-Customer-ID': getCurrentCustomerId()
      }
    });
    
    if (response.ok) {
      const data = await response.json();
      setSubscriptions(data.subscriptions || []);
    }
  };

  const loadInvoices = async () => {
    const response = await fetch('/api/v1/portal/invoices?limit=10', {
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`,
        'X-Customer-ID': getCurrentCustomerId()
      }
    });
    
    if (response.ok) {
      const data = await response.json();
      setInvoices(data.invoices || []);
    }
  };

  const loadPaymentMethods = async () => {
    const response = await fetch('/api/v1/portal/payment-methods', {
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`,
        'X-Customer-ID': getCurrentCustomerId()
      }
    });
    
    if (response.ok) {
      const data = await response.json();
      setPaymentMethods(data || []);
    }
  };

  const getCurrentCustomerId = () => {
    // This would typically come from JWT token or auth context
    return localStorage.getItem('customerId') || '';
  };

  const getStatusBadgeVariant = (status: string) => {
    switch (status.toLowerCase()) {
      case 'active':
        return 'default';
      case 'trialing':
        return 'secondary';
      case 'past_due':
        return 'destructive';
      case 'canceled':
        return 'secondary';
      case 'paid':
        return 'default';
      case 'open':
        return 'secondary';
      case 'overdue':
        return 'destructive';
      default:
        return 'outline';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'active':
      case 'paid':
        return <CheckCircle className="h-4 w-4" />;
      case 'trialing':
        return <Clock className="h-4 w-4" />;
      case 'past_due':
      case 'overdue':
        return <AlertCircle className="h-4 w-4" />;
      default:
        return null;
    }
  };

  if (loading) {
    return (
      <div className="container mx-auto p-6">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-gray-200 rounded w-1/4"></div>
          <div className="h-32 bg-gray-200 rounded"></div>
          <div className="h-64 bg-gray-200 rounded"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Billing Portal</h1>
          <p className="text-muted-foreground">
            Manage your account, subscriptions, and billing information
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Badge variant="outline" className="flex items-center gap-1">
            <Shield className="h-3 w-3" />
            {customer?.securityClearance?.toUpperCase()}
          </Badge>
        </div>
      </div>

      {/* Account Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Building2 className="h-4 w-4 text-muted-foreground" />
              <div className="space-y-1">
                <p className="text-sm font-medium">Active Subscriptions</p>
                <p className="text-2xl font-bold">{customer?.activeSubscriptions || 0}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <DollarSign className="h-4 w-4 text-muted-foreground" />
              <div className="space-y-1">
                <p className="text-sm font-medium">Account Balance</p>
                <p className="text-2xl font-bold">
                  {formatCurrency(customer?.accountBalance || 0, customer?.currency || 'USD')}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Calendar className="h-4 w-4 text-muted-foreground" />
              <div className="space-y-1">
                <p className="text-sm font-medium">Next Renewal</p>
                <p className="text-sm font-bold">
                  {customer?.nextRenewalDate 
                    ? formatDate(new Date(customer.nextRenewalDate))
                    : 'N/A'
                  }
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
              <div className="space-y-1">
                <p className="text-sm font-medium">Trial Subscriptions</p>
                <p className="text-2xl font-bold">{customer?.trialSubscriptions || 0}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full grid-cols-6">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="subscriptions">Subscriptions</TabsTrigger>
          <TabsTrigger value="invoices">Invoices</TabsTrigger>
          <TabsTrigger value="payments">Payment Methods</TabsTrigger>
          <TabsTrigger value="usage">Usage</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Recent Invoices */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  Recent Invoices
                  <Button variant="ghost" size="sm" onClick={() => setActiveTab('invoices')}>
                    View All <ChevronRight className="h-4 w-4 ml-1" />
                  </Button>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {invoices.slice(0, 5).map((invoice) => (
                  <div key={invoice.id} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="space-y-1">
                      <p className="font-medium">{invoice.invoiceNumber}</p>
                      <p className="text-sm text-muted-foreground">
                        Due: {formatDate(new Date(invoice.dueDate))}
                      </p>
                    </div>
                    <div className="text-right space-y-1">
                      <p className="font-medium">
                        {formatCurrency(invoice.totalAmount, invoice.currency)}
                      </p>
                      <Badge variant={getStatusBadgeVariant(invoice.status)} className="text-xs">
                        {getStatusIcon(invoice.status)}
                        <span className="ml-1">{invoice.status}</span>
                      </Badge>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>

            {/* Active Subscriptions */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  Active Subscriptions
                  <Button variant="ghost" size="sm" onClick={() => setActiveTab('subscriptions')}>
                    View All <ChevronRight className="h-4 w-4 ml-1" />
                  </Button>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {subscriptions.filter(sub => sub.status === 'active').slice(0, 3).map((subscription) => (
                  <div key={subscription.id} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="space-y-1">
                      <p className="font-medium">{subscription.plan?.name || 'Subscription'}</p>
                      <p className="text-sm text-muted-foreground">
                        Renews: {formatDate(new Date(subscription.currentPeriodEnd))}
                      </p>
                    </div>
                    <div className="text-right space-y-1">
                      <p className="font-medium">
                        {formatCurrency(subscription.unitAmount * subscription.quantity, subscription.currency)}
                      </p>
                      <Badge variant={getStatusBadgeVariant(subscription.status)} className="text-xs">
                        {getStatusIcon(subscription.status)}
                        <span className="ml-1">{subscription.status}</span>
                      </Badge>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Subscriptions Tab */}
        <TabsContent value="subscriptions" className="space-y-4">
          <SubscriptionsTab subscriptions={subscriptions} onUpdate={loadSubscriptions} />
        </TabsContent>

        {/* Invoices Tab */}
        <TabsContent value="invoices" className="space-y-4">
          <InvoicesTab invoices={invoices} onUpdate={loadInvoices} />
        </TabsContent>

        {/* Payment Methods Tab */}
        <TabsContent value="payments" className="space-y-4">
          <PaymentMethodsTab paymentMethods={paymentMethods} onUpdate={loadPaymentMethods} />
        </TabsContent>

        {/* Usage Tab */}
        <TabsContent value="usage" className="space-y-4">
          <UsageTab subscriptions={subscriptions} />
        </TabsContent>

        {/* Settings Tab */}
        <TabsContent value="settings" className="space-y-4">
          <SettingsTab customer={customer} onUpdate={loadCustomerInfo} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// Subscriptions Tab Component
function SubscriptionsTab({ subscriptions, onUpdate }: { subscriptions: Subscription[]; onUpdate: () => void }) {
  const { toast } = useToast();

  const handleCancelSubscription = async (subscriptionId: string) => {
    if (!confirm('Are you sure you want to cancel this subscription?')) {
      return;
    }

    try {
      const response = await fetch(`/api/v1/portal/subscriptions/${subscriptionId}/cancel`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'X-Customer-ID': localStorage.getItem('customerId') || ''
        },
        body: JSON.stringify({
          cancelAtPeriodEnd: true,
          cancellationReason: 'Customer requested cancellation'
        })
      });

      if (response.ok) {
        toast({
          title: 'Success',
          description: 'Subscription will be canceled at the end of the current billing period.'
        });
        onUpdate();
      } else {
        throw new Error('Failed to cancel subscription');
      }
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to cancel subscription. Please try again.',
        variant: 'destructive'
      });
    }
  };

  return (
    <div className="space-y-4">
      {subscriptions.map((subscription) => (
        <Card key={subscription.id}>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>{subscription.plan?.name || 'Subscription'}</CardTitle>
                <CardDescription>{subscription.plan?.description}</CardDescription>
              </div>
              <Badge variant={getStatusBadgeVariant(subscription.status)}>
                {subscription.status}
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <p className="font-medium">Amount</p>
                <p>{formatCurrency(subscription.unitAmount * subscription.quantity, subscription.currency)}</p>
              </div>
              <div>
                <p className="font-medium">Billing Cycle</p>
                <p>{subscription.plan?.interval || 'monthly'}</p>
              </div>
              <div>
                <p className="font-medium">Current Period</p>
                <p>{formatDate(new Date(subscription.currentPeriodStart))} - {formatDate(new Date(subscription.currentPeriodEnd))}</p>
              </div>
              <div>
                <p className="font-medium">Quantity</p>
                <p>{subscription.quantity}</p>
              </div>
            </div>

            {subscription.plan?.features && subscription.plan.features.length > 0 && (
              <div>
                <h4 className="font-medium mb-2">Features</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {subscription.plan.features.map((feature, index) => (
                    <div key={index} className="flex items-center gap-2 text-sm">
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      <span>{feature.name}</span>
                      {feature.limit && (
                        <span className="text-muted-foreground">({feature.limit})</span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <Separator />

            <div className="flex gap-2">
              <Button variant="outline" size="sm">
                <Settings className="h-4 w-4 mr-2" />
                Manage
              </Button>
              <Button variant="outline" size="sm">
                <Activity className="h-4 w-4 mr-2" />
                View Usage
              </Button>
              {subscription.status === 'active' && (
                <Button 
                  variant="destructive" 
                  size="sm"
                  onClick={() => handleCancelSubscription(subscription.id)}
                >
                  Cancel
                </Button>
              )}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// Invoices Tab Component
function InvoicesTab({ invoices, onUpdate }: { invoices: Invoice[]; onUpdate: () => void }) {
  const { toast } = useToast();

  const handleDownloadPDF = async (invoiceId: string, invoiceNumber: string) => {
    try {
      const response = await fetch(`/api/v1/portal/invoices/${invoiceId}/pdf`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'X-Customer-ID': localStorage.getItem('customerId') || ''
        }
      });

      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `invoice_${invoiceNumber}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      } else {
        throw new Error('Failed to download PDF');
      }
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to download invoice PDF. Please try again.',
        variant: 'destructive'
      });
    }
  };

  const handlePayInvoice = async (invoiceId: string) => {
    try {
      const response = await fetch(`/api/v1/portal/invoices/${invoiceId}/pay`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'X-Customer-ID': localStorage.getItem('customerId') || ''
        },
        body: JSON.stringify({})
      });

      if (response.ok) {
        const data = await response.json();
        if (data.requiresAction && data.clientSecret) {
          // Handle 3D Secure or other authentication
          // This would integrate with Stripe Elements
          toast({
            title: 'Authentication Required',
            description: 'Please complete the payment authentication.'
          });
        } else {
          toast({
            title: 'Success',
            description: 'Payment processed successfully.'
          });
          onUpdate();
        }
      } else {
        throw new Error('Failed to process payment');
      }
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to process payment. Please try again.',
        variant: 'destructive'
      });
    }
  };

  return (
    <div className="space-y-4">
      {invoices.map((invoice) => (
        <Card key={invoice.id}>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <h3 className="font-medium">{invoice.invoiceNumber}</h3>
                  <Badge variant={getStatusBadgeVariant(invoice.status)}>
                    {getStatusIcon(invoice.status)}
                    <span className="ml-1">{invoice.status}</span>
                  </Badge>
                </div>
                <p className="text-sm text-muted-foreground">
                  Issued: {formatDate(new Date(invoice.invoiceDate))} | 
                  Due: {formatDate(new Date(invoice.dueDate))}
                </p>
                <p className="text-sm text-muted-foreground">
                  Type: {invoice.invoiceType}
                </p>
              </div>
              
              <div className="text-right space-y-2">
                <div className="space-y-1">
                  <p className="text-lg font-bold">
                    {formatCurrency(invoice.totalAmount, invoice.currency)}
                  </p>
                  {invoice.amountDue > 0 && (
                    <p className="text-sm text-destructive">
                      Due: {formatCurrency(invoice.amountDue, invoice.currency)}
                    </p>
                  )}
                </div>
                
                <div className="flex gap-2">
                  <Button 
                    variant="outline" 
                    size="sm"
                    onClick={() => handleDownloadPDF(invoice.id, invoice.invoiceNumber)}
                    disabled={!invoice.pdfGenerated}
                  >
                    <Download className="h-4 w-4 mr-1" />
                    PDF
                  </Button>
                  <Button variant="ghost" size="sm">
                    <Eye className="h-4 w-4 mr-1" />
                    View
                  </Button>
                  {invoice.status === 'open' && invoice.amountDue > 0 && (
                    <Button 
                      size="sm"
                      onClick={() => handlePayInvoice(invoice.id)}
                    >
                      Pay Now
                    </Button>
                  )}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// Payment Methods Tab Component
function PaymentMethodsTab({ paymentMethods, onUpdate }: { paymentMethods: PaymentMethod[]; onUpdate: () => void }) {
  const { toast } = useToast();

  const handleDeletePaymentMethod = async (paymentMethodId: string) => {
    if (!confirm('Are you sure you want to delete this payment method?')) {
      return;
    }

    try {
      const response = await fetch(`/api/v1/portal/payment-methods/${paymentMethodId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'X-Customer-ID': localStorage.getItem('customerId') || ''
        }
      });

      if (response.ok) {
        toast({
          title: 'Success',
          description: 'Payment method deleted successfully.'
        });
        onUpdate();
      } else {
        throw new Error('Failed to delete payment method');
      }
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to delete payment method. Please try again.',
        variant: 'destructive'
      });
    }
  };

  const handleSetDefault = async (paymentMethodId: string) => {
    try {
      const response = await fetch(`/api/v1/portal/payment-methods/${paymentMethodId}/default`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'X-Customer-ID': localStorage.getItem('customerId') || ''
        }
      });

      if (response.ok) {
        toast({
          title: 'Success',
          description: 'Default payment method updated.'
        });
        onUpdate();
      } else {
        throw new Error('Failed to set default payment method');
      }
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to update default payment method. Please try again.',
        variant: 'destructive'
      });
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-medium">Payment Methods</h3>
        <Button>
          <CreditCard className="h-4 w-4 mr-2" />
          Add Payment Method
        </Button>
      </div>

      {paymentMethods.map((paymentMethod) => (
        <Card key={paymentMethod.id}>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <div className="p-2 bg-gray-100 rounded-lg">
                  <CreditCard className="h-6 w-6" />
                </div>
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <p className="font-medium">
                      {paymentMethod.cardBrand?.toUpperCase()} •••• {paymentMethod.cardLast4}
                    </p>
                    {paymentMethod.isDefault && (
                      <Badge variant="secondary">Default</Badge>
                    )}
                    <Badge variant={getStatusBadgeVariant(paymentMethod.status)}>
                      {paymentMethod.status}
                    </Badge>
                  </div>
                  <p className="text-sm text-muted-foreground">
                    Expires: {paymentMethod.cardExpMonth?.toString().padStart(2, '0')}/{paymentMethod.cardExpYear}
                  </p>
                  {paymentMethod.billingAddress && (
                    <p className="text-sm text-muted-foreground">
                      {paymentMethod.billingAddress.city}, {paymentMethod.billingAddress.state} {paymentMethod.billingAddress.postalCode}
                    </p>
                  )}
                </div>
              </div>

              <div className="flex gap-2">
                {!paymentMethod.isDefault && (
                  <Button 
                    variant="outline" 
                    size="sm"
                    onClick={() => handleSetDefault(paymentMethod.id)}
                  >
                    Set Default
                  </Button>
                )}
                <Button variant="outline" size="sm">
                  Edit
                </Button>
                <Button 
                  variant="destructive" 
                  size="sm"
                  onClick={() => handleDeletePaymentMethod(paymentMethod.id)}
                  disabled={paymentMethod.isDefault}
                >
                  Delete
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// Usage Tab Component
function UsageTab({ subscriptions }: { subscriptions: Subscription[] }) {
  const [selectedSubscription, setSelectedSubscription] = useState<string>('');
  const [usageData, setUsageData] = useState<UsageResponse | null>(null);
  const [loading, setLoading] = useState(false);

  const loadUsageData = async (subscriptionId: string) => {
    setLoading(true);
    try {
      const response = await fetch(`/api/v1/portal/subscriptions/${subscriptionId}/usage`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'X-Customer-ID': localStorage.getItem('customerId') || ''
        }
      });

      if (response.ok) {
        const data = await response.json();
        setUsageData(data);
      }
    } catch (error) {
      console.error('Failed to load usage data:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedSubscription) {
      loadUsageData(selectedSubscription);
    }
  }, [selectedSubscription]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-medium">Usage Tracking</h3>
        <select 
          className="border rounded-md px-3 py-2"
          value={selectedSubscription}
          onChange={(e) => setSelectedSubscription(e.target.value)}
        >
          <option value="">Select a subscription</option>
          {subscriptions.map((sub) => (
            <option key={sub.id} value={sub.id}>
              {sub.plan?.name || `Subscription ${sub.id.slice(0, 8)}`}
            </option>
          ))}
        </select>
      </div>

      {loading && (
        <div className="text-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto"></div>
        </div>
      )}

      {usageData && (
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Current Period Usage</CardTitle>
              <CardDescription>
                {formatDate(new Date(usageData.period.startDate))} - {formatDate(new Date(usageData.period.endDate))}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="text-center p-4 border rounded-lg">
                  <p className="text-2xl font-bold">{usageData.totalUsage.toLocaleString()}</p>
                  <p className="text-sm text-muted-foreground">Total Usage</p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <p className="text-2xl font-bold">{usageData.includedUsage.toLocaleString()}</p>
                  <p className="text-sm text-muted-foreground">Included</p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <p className="text-2xl font-bold text-orange-600">{usageData.overageUsage.toLocaleString()}</p>
                  <p className="text-sm text-muted-foreground">Overage</p>
                </div>
              </div>

              {usageData.overageAmount > 0 && (
                <div className="mt-4 p-4 bg-orange-50 border border-orange-200 rounded-lg">
                  <p className="font-medium text-orange-800">
                    Overage charges: {formatCurrency(usageData.overageAmount, usageData.currency)}
                  </p>
                  <p className="text-sm text-orange-600">
                    These charges will appear on your next invoice.
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          {usageData.usageItems.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Usage Breakdown</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {usageData.usageItems.map((item, index) => (
                    <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
                      <div>
                        <p className="font-medium">{item.metricName}</p>
                        <p className="text-sm text-muted-foreground">
                          {item.quantity.toLocaleString()} {item.metricUnit}
                        </p>
                      </div>
                      <div className="text-right">
                        <p className="font-medium">
                          {formatCurrency(item.amount, usageData.currency)}
                        </p>
                        {item.overageQuantity > 0 && (
                          <p className="text-sm text-orange-600">
                            +{item.overageQuantity.toLocaleString()} overage
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

// Settings Tab Component
function SettingsTab({ customer, onUpdate }: { customer: CustomerInfo | null; onUpdate: () => void }) {
  const [settings, setSettings] = useState({
    emailNotifications: true,
    invoiceReminders: true,
    usageAlerts: true,
    usageThreshold: 80,
    autoPayEnabled: false
  });

  const { toast } = useToast();

  const handleSaveSettings = async () => {
    try {
      const response = await fetch('/api/v1/portal/settings', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'X-Customer-ID': localStorage.getItem('customerId') || ''
        },
        body: JSON.stringify(settings)
      });

      if (response.ok) {
        toast({
          title: 'Success',
          description: 'Settings updated successfully.'
        });
      } else {
        throw new Error('Failed to update settings');
      }
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to update settings. Please try again.',
        variant: 'destructive'
      });
    }
  };

  return (
    <div className="space-y-6">
      {/* Account Information */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <User className="h-5 w-5" />
            Account Information
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-1">Name</label>
              <p className="text-sm p-2 border rounded bg-gray-50">{customer?.name}</p>
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Email</label>
              <p className="text-sm p-2 border rounded bg-gray-50">{customer?.email}</p>
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Phone</label>
              <p className="text-sm p-2 border rounded bg-gray-50">{customer?.phone || 'Not provided'}</p>
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Security Clearance</label>
              <Badge variant="outline">{customer?.securityClearance?.toUpperCase()}</Badge>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Notification Settings */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bell className="h-5 w-5" />
            Notification Preferences
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-3">
            <label className="flex items-center gap-2">
              <input 
                type="checkbox" 
                checked={settings.emailNotifications}
                onChange={(e) => setSettings({...settings, emailNotifications: e.target.checked})}
              />
              <span>Email notifications</span>
            </label>
            <label className="flex items-center gap-2">
              <input 
                type="checkbox" 
                checked={settings.invoiceReminders}
                onChange={(e) => setSettings({...settings, invoiceReminders: e.target.checked})}
              />
              <span>Invoice reminders</span>
            </label>
            <label className="flex items-center gap-2">
              <input 
                type="checkbox" 
                checked={settings.usageAlerts}
                onChange={(e) => setSettings({...settings, usageAlerts: e.target.checked})}
              />
              <span>Usage alerts</span>
            </label>
            <label className="flex items-center gap-2">
              <input 
                type="checkbox" 
                checked={settings.autoPayEnabled}
                onChange={(e) => setSettings({...settings, autoPayEnabled: e.target.checked})}
              />
              <span>Automatic payments</span>
            </label>
          </div>
          
          {settings.usageAlerts && (
            <div>
              <label className="block text-sm font-medium mb-1">
                Usage alert threshold ({settings.usageThreshold}%)
              </label>
              <input 
                type="range" 
                min="50" 
                max="100" 
                value={settings.usageThreshold}
                onChange={(e) => setSettings({...settings, usageThreshold: parseInt(e.target.value)})}
                className="w-full"
              />
            </div>
          )}
        </CardContent>
      </Card>

      <div className="flex justify-end">
        <Button onClick={handleSaveSettings}>
          Save Settings
        </Button>
      </div>
    </div>
  );
}