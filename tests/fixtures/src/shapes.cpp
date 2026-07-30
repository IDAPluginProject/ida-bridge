// shapes.cpp -- small C++ fixture for e2e tests.
//
// Adds C++ shapes to the fixture bank: a polymorphic class hierarchy (vtables,
// RTTI), virtual dispatch, and a template instantiation (mangled names). Gives
// the generic SQL suite a binary whose types/names differ from the C fixtures.
//
// Built into an arm64 variant by build.py.
#include <cstdio>

class Shape {
public:
    virtual ~Shape() = default;
    virtual double area() const = 0;
    virtual const char *name() const = 0;
};

class Circle : public Shape {
    double r_;

public:
    explicit Circle(double r) : r_(r) {}
    double area() const override { return 3.14159 * r_ * r_; }
    const char *name() const override { return "circle"; }
};

class Rectangle : public Shape {
    double w_, h_;

public:
    Rectangle(double w, double h) : w_(w), h_(h) {}
    double area() const override { return w_ * h_; }
    const char *name() const override { return "rectangle"; }
};

template <typename T>
static T max_value(T a, T b) {
    return a > b ? a : b;
}

double total_area(Shape **shapes, int n) {
    double total = 0.0;
    for (int i = 0; i < n; i++) {
        total += shapes[i]->area();
    }
    return total;
}

int main() {
    Circle c(2.0);
    Rectangle r(3.0, 4.0);
    Shape *shapes[] = {&c, &r};
    double total = total_area(shapes, 2);
    int m = max_value(3, 7);
    std::printf("shapes: %s %s total=%.2f max=%d\n", c.name(), r.name(), total, m);
    return 0;
}
