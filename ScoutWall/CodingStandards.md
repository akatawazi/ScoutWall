# Coding Standards

## Purpose

These standards define how we write C# code for applications that use SqlLite, MVC, and repository-backed models. The goal is to keep code easy to read, easy to maintain, and easy to reproduce through automated tooling.

## Core Principles

Code should be explicit, readable, and predictable.

We prefer names that clearly communicate the type or purpose of the object. We avoid abbreviations, unnecessary underscores, excessive dependency injection, and large controller methods. Business and processing logic should live in models, not controllers, views, or ViewModels.

## Technology Stack

The standard application stack is:

- C#
- SqlLite
- MVC pattern
- Repository-based model classes
- Data annotations for table, column, and key mapping

## Naming Standards

### C# Class Names

Class names use PascalCase.

```csharp
public class Customer
{
}
```

### Local Variables

Local variables use lower camelCase and should normally be based on the class name.

```csharp
var customer = new Customer();
var analyteGroup = new AnalyteGroup();
```

Do not use underscores for local variable names.

```csharp
// Correct
var customer = new Customer();

// Incorrect
var _customer = new Customer();
var customer_record = new Customer();
```

### Multiple Variables of the Same Type

When two variables of the same class are used in the same scope, prefix the class-based name with a clear qualifier.

```csharp
var oldCustomer = await Customer.Get(dataContext, customer => customer.Id == customerId);
var newCustomer = new Customer();
```

The root of the variable name should still be the original class name.

```csharp
// Correct
var oldCustomer = new Customer();
var newCustomer = new Customer();

// Avoid
var previous = new Customer();
var updated = new Customer();
```

### Avoid Underscores

Underscores should generally be avoided in C# code.

```csharp
// Correct
var dataContext = new DataContext();

// Incorrect
var data_context = new DataContext();
var _dataContext = new DataContext();
```

The main exception is database naming where SqlLite tables and columns may use snake_case. C# models map to those names through data annotations.

```csharp
[Column("group_number")]
public int GroupNumber { get; set; }
```

### Avoid Abbreviations

Do not abbreviate names when spelling them out makes the code easier to understand.

```csharp
// Correct
var dataContext = new DataContext();

// Incorrect
var dbContext = new DataContext();
```

Use names that make it obvious which class or concept is being used.

```csharp
// Correct
var customerReport = new CustomerReport();

// Incorrect
var cr = new CustomerReport();
```

## MVC Pattern

We use the MVC pattern.

### Controllers

Controllers should be extremely slender.

Controllers should:

- Receive the request
- Call the appropriate model or repository-backed model method
- Return the result or view

Controllers should not contain business logic, processing logic, or complex query logic.

```csharp
public class AnalyteGroupsController : Controller
{
    public async Task<IActionResult> Index(DataContext dataContext)
    {
        var analyteGroups = await AnalyteGroup.GetAll(dataContext);
        return View(analyteGroups);
    }
}
```

### Models

Models contain the processing logic.

A model is not just a data structure. It is the primary place for logic related to that entity.

Models should:

- Contain entity properties
- Use data annotations for SqlLite table and column mapping
- Inherit from `Repository<T>`
- Contain processing methods related to the model
- Keep logic close to the data it operates on

### Views

Views should be thin.

Views should display data and avoid processing logic. Any logic required to prepare the data should happen in the model before the view is rendered.

### ViewModels

Only use a ViewModel when more than one model needs to be passed into a view.

A ViewModel is only a container. It should not contain processing logic.

```csharp
public class CustomerDashboardViewModel
{
    public Customer Customer { get; set; } = new();
    public List<Order> Orders { get; set; } = new();
}
```

Do not create ViewModels unnecessarily when a single model is sufficient.

```csharp
// Correct when only one model is needed
return View(customer);

// Avoid
return View(new CustomerViewModel { Customer = customer });
```

## Repository Pattern

All models inherit from the generic repository.

The repository class contains the standard CRUD operations.

Typical repository operations include:

- `GetAll`
- `Get`
- `Insert`
- `Update`
- `Delete`
- `DeleteById`
- `Count`

Model classes inherit from `Repository<T>`.

```csharp
using MyBLSLab.Api.Data;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MyBLSLab.Api.Models;

[Table("analyte_groups", Schema = "public")]
public class AnalyteGroup : Repository<AnalyteGroup>
{
    [Key]
    [Column("id")]
    public Guid Id { get; set; }

    [Column("group_number")]
    public int GroupNumber { get; set; }

    [Column("name")]
    public string Name { get; set; } = string.Empty;

    [Column("is_active")]
    public bool IsActive { get; set; }

    [Column("display_order")]
    public int DisplayOrder { get; set; }

    [Column("created_at")]
    public DateTime CreatedAt { get; set; }

    [Column("updated_at")]
    public DateTime UpdatedAt { get; set; }

    [Column("tenant_id")]
    public Guid TenantId { get; set; }
}
```

## Data Annotation Standards

Use data annotations wherever possible.

Every model that maps to a SqlLite table should include a `[Table]` attribute.

```csharp
[Table("analyte_groups", Schema = "public")]
public class AnalyteGroup : Repository<AnalyteGroup>
{
}
```

Every mapped property should include a `[Column]` attribute.

```csharp
[Column("display_order")]
public int DisplayOrder { get; set; }
```

Primary keys should use `[Key]`.

```csharp
[Key]
[Column("id")]
public Guid Id { get; set; }
```

C# property names should use PascalCase. SqlLite column names may use snake_case and should be mapped explicitly with `[Column]`.

## SqlLite Mapping

SqlLite table and column names may use snake_case.

C# code should not copy the SqlLite naming style. Instead, use PascalCase properties and map them with data annotations.

```csharp
[Column("created_at")]
public DateTime CreatedAt { get; set; }
```

This keeps C# readable while preserving compatibility with SqlLite naming conventions.

## Static Classes and Static Methods

Use static classes and static methods where practical.

We prefer static access patterns when they make the code simpler, clearer, and easier to automate.

```csharp
var analyteGroups = await AnalyteGroup.GetAll(dataContext);
```

Avoid unnecessary object construction when the operation is naturally stateless or repository-driven.

## Dependency Injection

Avoid dependency injection unless it provides a clear benefit.

The preferred pattern is to keep dependencies explicit and simple. For example, pass `DataContext` into repository or model methods rather than hiding it behind multiple injected services.

```csharp
var analyteGroup = await AnalyteGroup.Get(dataContext, item => item.Id == id);
```

Dependency injection may be used when needed, but it should not be the default solution for every class.

## Processing Logic

Processing logic belongs in the model.

Controllers, views, and ViewModels should remain thin.

```csharp
public class Customer : Repository<Customer>
{
    public static async Task<Customer?> GetActiveCustomer(
        DataContext dataContext,
        Guid customerId)
    {
        return await Get(
            dataContext,
            customer => customer.Id == customerId && customer.IsActive
        );
    }
}
```

The controller should call the model method rather than implementing the logic directly.

```csharp
public async Task<IActionResult> Details(Guid id, DataContext dataContext)
{
    var customer = await Customer.GetActiveCustomer(dataContext, id);

    if (customer == null)
        return NotFound();

    return View(customer);
}
```

## Cyclomatic Complexity

Keep cyclomatic complexity as low as possible.

Methods should be easy to read, test, and replicate through automated processes.

Prefer:

- Small methods
- Clear names
- Early returns
- Simple conditionals
- Model-level helper methods
- Avoiding deeply nested code

```csharp
public bool CanBeDisplayed()
{
    if (!IsActive)
        return false;

    if (DisplayOrder < 0)
        return false;

    return true;
}
```

Avoid large methods with many nested branches.

## File Organization

Organize code around the MVC pattern and the model/repository structure.

Typical folders:

```text
Data/
    DataContext.cs
    Repository.cs

Models/
    AnalyteGroup.cs
    Customer.cs

Controllers/
    AnalyteGroupsController.cs
    CustomersController.cs

ViewModels/
    CustomerDashboardViewModel.cs

Views/
    AnalyteGroups/
    Customers/
```

## General Code Style

Use clear, descriptive names.

```csharp
// Correct
var activeCustomerReports = await CustomerReport.GetAll(
    dataContext,
    customerReport => customerReport.IsActive
);

// Avoid
var acr = await CustomerReport.GetAll(
    db,
    x => x.IsActive
);
```

Avoid unnecessary abbreviations.

```csharp
// Correct
var transactionAmount = transaction.Amount;

// Incorrect
var transAmt = transaction.Amount;
```

Avoid vague variable names except in very small, obvious lambda expressions.

```csharp
// Preferred
customer => customer.IsActive

// Acceptable for very small generic expressions
item => item.IsActive
```

## Standard Model Checklist

A model should generally meet the following standards:

- Uses PascalCase class name
- Inherits from `Repository<ModelName>`
- Has a `[Table]` attribute
- Has `[Column]` attributes on mapped properties
- Has `[Key]` on the primary key
- Uses PascalCase property names
- Contains model-specific processing logic
- Avoids unnecessary abbreviations
- Avoids underscores in C# names
- Keeps SqlLite snake_case isolated to data annotations

## Standard Controller Checklist

A controller should generally meet the following standards:

- Stays slender
- Does not contain business logic
- Calls model methods
- Returns views or API results
- Avoids complex conditionals
- Avoids direct SQL
- Avoids processing logic that belongs in the model

## Standard ViewModel Checklist

A ViewModel should generally meet the following standards:

- Only exists when a view needs more than one model
- Contains no processing logic
- Acts only as a container
- Uses clear model-based property names
- Avoids unnecessary abstraction

## Summary

The preferred architecture is simple and direct:

- C# models map to SqlLite tables through data annotations
- Models inherit from `Repository<T>`
- Repository provides basic CRUD behavior
- Models contain processing logic
- Controllers are slender
- Views are thin
- ViewModels are only containers for multiple models
- Naming is explicit, readable, and avoids abbreviations
- Underscores are avoided in C# code
- Cyclomatic complexity is kept low
