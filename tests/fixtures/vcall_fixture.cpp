// Virtual calls whose receivers are known (docs/verification-fixtures.md).
// Shape and Gadget both have a virtual method in slot 1, so a call through slot 1
// is a Shape call only when its receiver is a Shape: fx_sides_of, fx_sides_global and
// fx_sides_made are; fx_gadget_run is not.
//
// Trace fixture addition (spec 15.4, docs/trace-fixtures.md): Store::value is written by two overloads of
// Counter::put. put(int) is a plain member called directly (fx_put_direct); put(long long) is virtual, in slot 2 of
// Store, and is reached only through the base pointer (fx_put_slot). A hook on the first never sees the second.
// With a second argument the program stops after that many frames and prints its final state.
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

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

struct Store {
    int value = 0;
    virtual int get() { return value; }
    virtual void put(long long v) { value = (int)v; }
    virtual ~Store() {}
};
struct Counter : Store {
    __declspec(noinline) void put(int v) { value = v * 2; }
    __declspec(noinline) void put(long long v) override { value = (int)v * 3; }
};

Square g_square;
Counter g_counter;
volatile int g_sink;

extern "C" {
FX int fx_area_of(Shape *shape) { return shape->area(); }
FX int fx_sides_of(Shape *shape) { return shape->sides(); }
FX int fx_sides_global() { return g_square.sides() + static_cast<Shape &>(g_square).sides(); }
FX Shape *fx_make_shape(int kind) { return kind ? static_cast<Shape *>(new Triangle()) : new Square(); }
FX int fx_sides_made(int kind) { Shape *shape = fx_make_shape(kind); int n = shape->sides(); delete shape; return n; }
FX int fx_gadget_run(Gadget *gadget) { return gadget->run(); }
FX void fx_put_direct(Counter *counter, int v) { counter->put(v); }
FX void fx_put_slot(Store *store, long long v) { store->put(v); }
FX int fx_store_get(Store *store) { return store->get(); }
}

int main(int argc, char **argv) {
    Triangle triangle;
    Gadget gadget;
    for (int frame = 0; frame < 12000; ++frame) {
        if (argc > 1 && GetFileAttributesA(argv[1]) != INVALID_FILE_ATTRIBUTES) break;
        g_sink = fx_area_of(&triangle) + fx_sides_of(&g_square) + fx_sides_global()
               + fx_sides_made(frame & 1) + fx_gadget_run(&gadget);
        if (argc > 2) {
            fx_put_direct(&g_counter, frame + 1);
            printf("FX frame=%d direct=%d\n", frame, fx_store_get(&g_counter));
            fx_put_slot(&g_counter, frame + 1);
            printf("FX frame=%d slot=%d\n", frame, fx_store_get(&g_counter));
            fflush(stdout);
            if (frame + 1 >= atoi(argv[2])) break;
        }
        Sleep(argc > 2 ? 1 : 50);
    }
    return 0;
}
