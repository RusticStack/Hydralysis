// Virtual calls whose receivers are known (docs/verification-fixtures.md).
// Shape and Gadget both have a virtual method in slot 1, so a call through slot 1
// is a Shape call only when its receiver is a Shape: fx_sides_of, fx_sides_global and
// fx_sides_made are; fx_gadget_run is not.
#include <windows.h>

#define FX __declspec(noinline)

struct Shape {
    virtual int area() = 0;
    virtual int sides() = 0;
    virtual ~Shape() {}
};
struct Square : Shape {
    int side = 3;
    int area() override { return side * side; }
    int sides() override { return 4; }
};
struct Triangle : Shape {
    int base = 4, height = 5;
    int area() override { return base * height / 2; }
    int sides() override { return 3; }
};
struct Gadget {
    virtual int id() { return 1; }
    virtual int run() { return 2; }
    virtual ~Gadget() {}
};

Square g_square;
volatile int g_sink;

extern "C" {
FX int fx_area_of(Shape *shape) { return shape->area(); }
FX int fx_sides_of(Shape *shape) { return shape->sides(); }
FX int fx_sides_global() { return g_square.sides() + static_cast<Shape &>(g_square).sides(); }
FX Shape *fx_make_shape(int kind) { return kind ? static_cast<Shape *>(new Triangle()) : new Square(); }
FX int fx_sides_made(int kind) { Shape *shape = fx_make_shape(kind); int n = shape->sides(); delete shape; return n; }
FX int fx_gadget_run(Gadget *gadget) { return gadget->run(); }
}

int main(int argc, char **argv) {
    Triangle triangle;
    Gadget gadget;
    for (int frame = 0; frame < 12000; ++frame) {
        if (argc > 1 && GetFileAttributesA(argv[1]) != INVALID_FILE_ATTRIBUTES) break;
        g_sink = fx_area_of(&triangle) + fx_sides_of(&g_square) + fx_sides_global()
               + fx_sides_made(frame & 1) + fx_gadget_run(&gadget);
        Sleep(50);
    }
    return 0;
}
