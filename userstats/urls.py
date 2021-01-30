from .views import  ExpenseSummaryStats,IncomeSourceSummaryStats
from  django.urls import  path
urlpatterns=[
    path('expenses_category_data',ExpenseSummaryStats.as_view(),name="expense-category-summary"),
    path('income_category_data', IncomeSourceSummaryStats.as_view(), name="income-category-summary")

]