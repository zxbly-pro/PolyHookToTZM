#pragma once
#include "../resources/imgui/imgui.h"
#pragma warning(disable:4244)

enum
{
    FL_NONE = 1 << 0,
    FL_SHADOW = 1 << 1,
    FL_OUTLINE = 1 << 2,
    FL_CENTER_X = 1 << 3,
    FL_CENTER_Y = 1 << 4
};
//世界坐标转屏幕坐标
bool WorldToScreen(float position[3], float screen[2], float matrix[16], int windowWidth, int windowHeight);
//绘制Text
void DrawTextVal(int x, int y, const ImColor& color, const char* val);
//添加图片
void AddImage(const ImVec2& position, const ImVec2& size, const ImTextureID pTexture, const ImColor& color);
//添加填充圆
void AddCircleFilled(const ImVec2& position, float radius, const ImColor& color, int segments = 100);
//添加圆
void AddCircle(const ImVec2& position, float radius, const ImColor& color, int segments = 100);
//添加填充矩形
void AddRectFilled(const ImVec2& position, const ImVec2& size, const ImColor& color, float rounding = 0.f);
//添加渐变填充矩形
void AddRectFilledGradient(const ImVec2& position, const ImVec2& size, const ImColor& leftTop, const ImColor& rightTop, const ImColor& leftBot, const ImColor& rightBot);
//绘制填充矩形区域
void DrawFillArea(float x, float y, float w, float h, const ImColor& color, float rounding = 0.f);
//绘制渐变填充区域
void DrawFillAreaGradient(float x, float y, float w, float h, const ImColor& leftTop, const ImColor& rightTop, const ImColor& leftBot, const ImColor& rightBot);
//添加三角形
void AddTriangle(const ImVec2& a, const ImVec2& b, const ImVec2& c, const ImColor& color);
//添加填充三角形
void AddTriangleFilled(const ImVec2& a, const ImVec2& b, const ImVec2& c, const ImColor& color);
//添加线
void AddLine(const ImVec2& from, const ImVec2& to, const ImColor& color, float thickness = 1.f);
//添加文本
void AddText(float x, float y, const ImColor& color, float fontSize, int flags, const char* format, ...);
//添加矩形
void AddRect(const ImVec2& position, const ImVec2& size, const ImColor& color, float rounding = 0.f);
//绘制方框
void DrawBox(float x, float y, float w, float h, const ImColor& color);
//绘制方框输出线
void DrawBoxOutline(float x, float y, float w, float h, const ImColor& color);
//绘制圆形框
void DrawRoundBox(float x, float y, float w, float h, const ImColor& color, float rounding);
//绘制圆形框输出线
void DrawRoundBoxOutline(float x, float y, float w, float h, const ImColor& color, float rounding);
//绘制方框角
void DrawCornerBox(float x, float y, float w, float h, const ImColor& color);
//绘制方框角输出线
void DrawCornerBoxOutline(float x, float y, float w, float h, const ImColor& color);
//绘制人物框
void DrawEspBox(int box_type, float x, float y, float w, float h, float r, float g, float b, float a);
//绘制点
void DrawDot(int x, int y, const ImColor& color);
//绘制3D框
void Draw3DBox(int x, int y,int w,int h,int offset, const ImColor& color);

