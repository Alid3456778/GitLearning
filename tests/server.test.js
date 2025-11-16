// const request = require("supertest");
// const { app } = require("../server"); // uses your exported app


// const request = require("supertest");
// const { app } = require("../server");

const request = require("supertest");
const { app, server } = require("../server");
const mongoose = require("mongoose");


let userToken = "";
let createdProductId = "";
let adminToken = "";

describe("Basic Server Tests", () => {

  // Simple test to check if API is responding
  it("should respond to GET /api/products", async () => {
    const res = await request(app).get("/api/products");

    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty("products");
  });

  // Test invalid route
  it("should return 404 for unknown route", async () => {
    const res = await request(app).get("/random-route-not-exist");

    expect(res.statusCode).toBe(404);
    expect(res.body.message).toBe("Route not found");
  });

});

// ================================
//  ADMIN LOGIN TEST
// ================================
describe("Admin Login Test", () => {
  it("should login admin successfully", async () => {
    const res = await request(app)
      .post("/api/admin/login")
      .send({ username: "admin", password: "admin123" });

    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty("token");

    adminToken = res.body.token;
  });
});

// ================================
//  USER REGISTER + LOGIN TEST
// ================================
describe("User Auth Tests", () => {
  const testEmail = `test${Date.now()}@gmail.com`;

  it("should register a new user", async () => {
    const res = await request(app)
      .post("/api/auth/register")
      .send({
        name: "Test User",
        email: testEmail,
        password: "123456"
      });

    expect(res.statusCode).toBe(201);
    expect(res.body).toHaveProperty("token");
  });

  it("should login user successfully", async () => {
    const res = await request(app)
      .post("/api/auth/login")
      .send({
        email: testEmail,
        password: "123456"
      });

    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty("token");

    userToken = res.body.token;
  });
});

// ================================
//  ADMIN PRODUCT ACTIONS
// ================================
describe("Admin Product Routes", () => {

  it("Admin should add a new product", async () => {
    const res = await request(app)
      .post("/api/admin/products")
      .set("Authorization", `Bearer ${adminToken}`)
      .field("name", "Test Product")
      .field("price", "100")
      .field("category", "Test Category")
      .field("stock", "10");

    expect(res.statusCode).toBe(201);
    expect(res.body.product).toHaveProperty("_id");

    createdProductId = res.body.product._id;
  });

  it("Admin should update the product", async () => {
    const res = await request(app)
      .put(`/api/admin/products/${createdProductId}`)
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ price: 150 });

    expect(res.statusCode).toBe(200);
    expect(res.body.product.price).toBe(150);
  });

  it("Admin should get all products", async () => {
    const res = await request(app)
      .get("/api/admin/products")
      .set("Authorization", `Bearer ${adminToken}`);

    expect(res.statusCode).toBe(200);
    expect(res.body.products.length).toBeGreaterThan(0);
  });
});

// ================================
//  PUBLIC PRODUCT ROUTES
// ================================
describe("Public Product Routes", () => {
  it("should get all products", async () => {
    const res = await request(app).get("/api/products");

    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty("products");
  });

  it("should get product by ID", async () => {
    const res = await request(app).get(`/api/products/${createdProductId}`);

    expect(res.statusCode).toBe(200);
    expect(res.body._id).toBe(createdProductId);
  });
});

// ================================
//  CART ROUTES (User Token Required)
// ================================
describe("Cart Routes", () => {
  it("should add product to cart", async () => {
    const res = await request(app)
      .post("/api/cart/add")
      .set("Authorization", `Bearer ${userToken}`)
      .send({
        productId: createdProductId,
        quantity: 1
      });

    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty("cart");
  });

  it("should get cart", async () => {
    const res = await request(app)
      .get("/api/cart")
      .set("Authorization", `Bearer ${userToken}`);

    expect(res.statusCode).toBe(200);
    expect(res.body.items.length).toBeGreaterThan(0);
  });
});

// ================================
//  WISHLIST ROUTES
// ================================
describe("Wishlist Routes", () => {
  it("should add product to wishlist", async () => {
    const res = await request(app)
      .post("/api/wishlist/add")
      .set("Authorization", `Bearer ${userToken}`)
      .send({ productId: createdProductId });

    expect(res.statusCode).toBe(200);
  });

  it("should get wishlist", async () => {
    const res = await request(app)
      .get("/api/wishlist")
      .set("Authorization", `Bearer ${userToken}`);

    expect(res.statusCode).toBe(200);
    expect(res.body.total).toBeGreaterThan(0);
  });
});

// ================================
//  DELETE PRODUCT (ADMIN)
// ================================
describe("Admin Delete Product", () => {
  it("should delete product", async () => {
    const res = await request(app)
      .delete(`/api/admin/products/${createdProductId}`)
      .set("Authorization", `Bearer ${adminToken}`);

    expect(res.statusCode).toBe(200);
  });
});

afterAll(async () => {
  await mongoose.connection.close(); // closes database
  server.close();                    // closes express server
});

