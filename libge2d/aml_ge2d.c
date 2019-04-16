/*
 * Copyright (c) 2014 Amlogic, Inc. All rights reserved.
 *
 * This source code is subject to the terms and conditions defined in the
 * file 'LICENSE' which is part of this source code package.
 *
 * Description:
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <malloc.h>
#include "include/ge2d_port.h"
#include "include/ge2d_com.h"
#include "include/dmabuf.h"
#include <IONmem.h>
#include "include/aml_ge2d.h"
#include "kernel-headers/linux/ge2d.h"

#define CANVAS_ALIGNED(x)	(((x) + 31) & ~31)

static int fd_ge2d = -1;

static void ge2d_setinfo_size(aml_ge2d_t *pge2d)
{
    unsigned int input_image_width  = 0, input2_image_width = 0, output_image_width = 0;

    if (GE2D_CANVAS_ALLOC == pge2d->ge2dinfo.src_info[0].memtype) {
        input_image_width  = pge2d->ge2dinfo.src_info[0].canvas_w;
        if ((pge2d->ge2dinfo.src_info[0].format == PIXEL_FORMAT_RGBA_8888) ||
            (pge2d->ge2dinfo.src_info[0].format == PIXEL_FORMAT_BGRA_8888) ||
            (pge2d->ge2dinfo.src_info[0].format == PIXEL_FORMAT_RGBX_8888))
            pge2d->src_size = CANVAS_ALIGNED(input_image_width * 4) * pge2d->ge2dinfo.src_info[0].canvas_h;
        else if ((pge2d->ge2dinfo.src_info[0].format == PIXEL_FORMAT_RGB_565) ||
            (pge2d->ge2dinfo.src_info[0].format == PIXEL_FORMAT_YCbCr_422_UYVY) ||
            (pge2d->ge2dinfo.src_info[0].format == PIXEL_FORMAT_YCbCr_422_SP))
            pge2d->src_size = CANVAS_ALIGNED(input_image_width * 2) * pge2d->ge2dinfo.src_info[0].canvas_h;
        else if ((pge2d->ge2dinfo.src_info[0].format == PIXEL_FORMAT_RGB_888)
            || (pge2d->ge2dinfo.src_info[0].format == PIXEL_FORMAT_BGR_888))
            pge2d->src_size = CANVAS_ALIGNED(input_image_width * 3) * pge2d->ge2dinfo.src_info[0].canvas_h;
        else if ((pge2d->ge2dinfo.src_info[0].format == PIXEL_FORMAT_YCrCb_420_SP) ||
            (pge2d->ge2dinfo.src_info[0].format == PIXEL_FORMAT_YCbCr_420_SP_NV12) ||
            (pge2d->ge2dinfo.src_info[0].format == PIXEL_FORMAT_YV12))
            pge2d->src_size = CANVAS_ALIGNED(input_image_width * 3 / 2) * pge2d->ge2dinfo.src_info[0].canvas_h;
        else if (pge2d->ge2dinfo.src_info[0].format == PIXEL_FORMAT_Y8)
            pge2d->src_size = CANVAS_ALIGNED(input_image_width) * pge2d->ge2dinfo.src_info[0].canvas_h;
        else {
            E_GE2D("%s,%d,format not support now\n",__func__, __LINE__);
            return;
        }
    }

    if (GE2D_CANVAS_ALLOC == pge2d->ge2dinfo.src_info[1].memtype) {
        input2_image_width  = pge2d->ge2dinfo.src_info[1].canvas_w;
        if ((pge2d->ge2dinfo.src_info[1].format == PIXEL_FORMAT_RGBA_8888) ||
            (pge2d->ge2dinfo.src_info[1].format == PIXEL_FORMAT_BGRA_8888) ||
            (pge2d->ge2dinfo.src_info[1].format == PIXEL_FORMAT_RGBX_8888))
            pge2d->src2_size = CANVAS_ALIGNED(input2_image_width * 4) * pge2d->ge2dinfo.src_info[1].canvas_h;
        else if ((pge2d->ge2dinfo.src_info[1].format == PIXEL_FORMAT_RGB_565) ||
            (pge2d->ge2dinfo.src_info[1].format == PIXEL_FORMAT_YCbCr_422_UYVY) ||
            (pge2d->ge2dinfo.src_info[1].format == PIXEL_FORMAT_YCbCr_422_SP))
            pge2d->src2_size = CANVAS_ALIGNED(input2_image_width * 2) * pge2d->ge2dinfo.src_info[1].canvas_h;
        else if ((pge2d->ge2dinfo.src_info[1].format == PIXEL_FORMAT_RGB_888)
            || (pge2d->ge2dinfo.src_info[0].format == PIXEL_FORMAT_BGR_888))
            pge2d->src2_size = CANVAS_ALIGNED(input2_image_width * 3) * pge2d->ge2dinfo.src_info[1].canvas_h;
        else if ((pge2d->ge2dinfo.src_info[1].format == PIXEL_FORMAT_YCrCb_420_SP) ||
            (pge2d->ge2dinfo.src_info[1].format == PIXEL_FORMAT_YCbCr_420_SP_NV12) ||
            (pge2d->ge2dinfo.src_info[1].format == PIXEL_FORMAT_YV12))
            pge2d->src2_size = CANVAS_ALIGNED(input2_image_width * 3 / 2) * pge2d->ge2dinfo.src_info[1].canvas_h;
        else if (pge2d->ge2dinfo.src_info[1].format == PIXEL_FORMAT_Y8)
            pge2d->src2_size = CANVAS_ALIGNED(input2_image_width) * pge2d->ge2dinfo.src_info[1].canvas_h;
        else {
            E_GE2D("%s,%d,format not support now\n",__func__, __LINE__);
            return;
        }
    }

    if (GE2D_CANVAS_ALLOC == pge2d->ge2dinfo.dst_info.memtype) {
        output_image_width = pge2d->ge2dinfo.dst_info.canvas_w;
        if ((pge2d->ge2dinfo.dst_info.format == PIXEL_FORMAT_RGBA_8888) ||
            (pge2d->ge2dinfo.dst_info.format == PIXEL_FORMAT_BGRA_8888) ||
            (pge2d->ge2dinfo.dst_info.format == PIXEL_FORMAT_RGBX_8888))
            pge2d->dst_size = CANVAS_ALIGNED(output_image_width * 4) * pge2d->ge2dinfo.dst_info.canvas_h;
        else if ((pge2d->ge2dinfo.dst_info.format == PIXEL_FORMAT_RGB_565) ||
            (pge2d->ge2dinfo.dst_info.format == PIXEL_FORMAT_YCbCr_422_UYVY) ||
            (pge2d->ge2dinfo.dst_info.format == PIXEL_FORMAT_YCbCr_422_SP))
            pge2d->dst_size = CANVAS_ALIGNED(output_image_width * 2) * pge2d->ge2dinfo.dst_info.canvas_h;
        else if ((pge2d->ge2dinfo.dst_info.format == PIXEL_FORMAT_RGB_888)
            || (pge2d->ge2dinfo.dst_info.format == PIXEL_FORMAT_BGR_888))
            pge2d->dst_size = CANVAS_ALIGNED(output_image_width * 3) * pge2d->ge2dinfo.dst_info.canvas_h;
        else if ((pge2d->ge2dinfo.dst_info.format == PIXEL_FORMAT_YCrCb_420_SP) ||
            (pge2d->ge2dinfo.dst_info.format == PIXEL_FORMAT_YCbCr_420_SP_NV12) ||
            (pge2d->ge2dinfo.dst_info.format == PIXEL_FORMAT_YV12))
            pge2d->dst_size = CANVAS_ALIGNED(output_image_width * 3 / 2) * pge2d->ge2dinfo.dst_info.canvas_h;
        else if (pge2d->ge2dinfo.dst_info.format == PIXEL_FORMAT_Y8)
            pge2d->dst_size = CANVAS_ALIGNED(output_image_width) * pge2d->ge2dinfo.dst_info.canvas_h;

        else {
            E_GE2D("%s,%d,format not support now\n",__func__, __LINE__);
            return;
        }
    }
    return;
}

static void ge2d_mem_free(aml_ge2d_t *pge2d)
{
    if (pge2d->src_size && (pge2d->ge2dinfo.src_info[0].mem_alloc_type == AML_GE2D_MEM_ION)) {
        free((IONMEM_AllocParams*)pge2d->cmemParm_src);
        pge2d->cmemParm_src = NULL;
    }
    if (pge2d->src2_size && (pge2d->ge2dinfo.src_info[1].mem_alloc_type == AML_GE2D_MEM_ION)) {
        free((IONMEM_AllocParams*)pge2d->cmemParm_src2);
        pge2d->cmemParm_src2 = NULL;
    }
    if (pge2d->dst_size && (pge2d->ge2dinfo.dst_info.mem_alloc_type == AML_GE2D_MEM_ION)) {
        free((IONMEM_AllocParams*)pge2d->cmemParm_dst);
        pge2d->cmemParm_dst = NULL;
    }
    if (pge2d->ge2dinfo.src_info[0].vaddr)
        munmap(pge2d->ge2dinfo.src_info[0].vaddr, pge2d->src_size);
    if (pge2d->ge2dinfo.src_info[1].vaddr)
        munmap(pge2d->ge2dinfo.src_info[1].vaddr, pge2d->src2_size);
    if (pge2d->ge2dinfo.dst_info.vaddr)
        munmap(pge2d->ge2dinfo.dst_info.vaddr, pge2d->dst_size);
    if (pge2d->ge2dinfo.src_info[0].shared_fd > 0)
        close(pge2d->ge2dinfo.src_info[0].shared_fd);
    if (pge2d->ge2dinfo.src_info[1].shared_fd > 0)
        close(pge2d->ge2dinfo.src_info[1].shared_fd);
    if (pge2d->ge2dinfo.dst_info.shared_fd > 0)
        close(pge2d->ge2dinfo.dst_info.shared_fd);

    D_GE2D("ge2d_mem_free!\n");
}

int aml_ge2d_init(void)
{
    int ret = -1;
    fd_ge2d = ge2d_open();
    if (fd_ge2d < 0)
        return ge2d_fail;
    ret = CMEM_init();
    if (ret < 0)
        return ge2d_fail;
    ret = dmabuf_init();
    if (ret < 0)
        return ge2d_fail;
    return ge2d_success;
}


void aml_ge2d_exit(void)
{
    if (fd_ge2d >= 0)
        ge2d_close(fd_ge2d);
    CMEM_exit();
    dmabuf_exit();
}

int aml_ge2d_get_cap(void)
{
    return ge2d_get_cap(fd_ge2d);
}


void aml_ge2d_mem_free_ion(aml_ge2d_t *pge2d)
{
    if (pge2d->src_size) {
        free((IONMEM_AllocParams*)pge2d->cmemParm_src);
        pge2d->cmemParm_src = NULL;
    }
    if (pge2d->src2_size) {
        free((IONMEM_AllocParams*)pge2d->cmemParm_src2);
        pge2d->cmemParm_src2 = NULL;
    }
    if (pge2d->dst_size) {
        free((IONMEM_AllocParams*)pge2d->cmemParm_dst);
        pge2d->cmemParm_dst = NULL;
    }
    if (pge2d->ge2dinfo.src_info[0].vaddr)
        munmap(pge2d->ge2dinfo.src_info[0].vaddr, pge2d->src_size);
    if (pge2d->ge2dinfo.src_info[1].vaddr)
        munmap(pge2d->ge2dinfo.src_info[1].vaddr, pge2d->src2_size);
    if (pge2d->ge2dinfo.dst_info.vaddr)
        munmap(pge2d->ge2dinfo.dst_info.vaddr, pge2d->dst_size);

}

int aml_ge2d_mem_alloc_ion(aml_ge2d_t *pge2d)
{
    int ret = -1;
    unsigned int nbytes = 0;

    ge2d_setinfo_size(pge2d);

    if (pge2d->src_size) {
        pge2d->cmemParm_src = malloc(sizeof(IONMEM_AllocParams));
        ret = CMEM_alloc(pge2d->src_size, pge2d->cmemParm_src, false);
        if (ret < 0) {
            E_GE2D("%s,%d,Not enough memory\n",__func__, __LINE__);
            goto exit;
        }
        pge2d->ge2dinfo.src_info[0].shared_fd = ((IONMEM_AllocParams*)pge2d->cmemParm_src)->mImageFd;
        pge2d->ge2dinfo.src_info[0].vaddr = (char*)mmap( NULL, pge2d->src_size,
            PROT_READ | PROT_WRITE, MAP_SHARED, ((IONMEM_AllocParams*)pge2d->cmemParm_src)->mImageFd, 0);

        if (!pge2d->ge2dinfo.src_info[0].vaddr) {
            E_GE2D("%s,%d,mmap failed,Not enough memory\n",__func__, __LINE__);
            goto exit;
        }
    }

    if (pge2d->src2_size) {
        pge2d->cmemParm_src2 = malloc(sizeof(IONMEM_AllocParams));
        ret = CMEM_alloc(pge2d->src2_size, pge2d->cmemParm_src2, false);
        if (ret < 0) {
            E_GE2D("%s,%d,Not enough memory\n",__func__, __LINE__);
            goto exit;
        }
        pge2d->ge2dinfo.src_info[1].shared_fd = ((IONMEM_AllocParams*)pge2d->cmemParm_src2)->mImageFd;
        pge2d->ge2dinfo.src_info[1].vaddr = (char*)mmap( NULL, pge2d->src2_size,
            PROT_READ | PROT_WRITE, MAP_SHARED, ((IONMEM_AllocParams*)pge2d->cmemParm_src2)->mImageFd, 0);
        if (!pge2d->ge2dinfo.src_info[1].vaddr) {
            E_GE2D("%s,%d,mmap failed,Not enough memory\n",__func__, __LINE__);
            goto exit;
        }
    }


    if (pge2d->dst_size) {
        pge2d->cmemParm_dst = malloc(sizeof(IONMEM_AllocParams));
        ret = CMEM_alloc(pge2d->dst_size, pge2d->cmemParm_dst, true);
        if (ret < 0) {
            E_GE2D("%s,%d,Not enough memory\n",__func__, __LINE__);
            goto exit;
        }
        pge2d->ge2dinfo.dst_info.shared_fd = ((IONMEM_AllocParams*)pge2d->cmemParm_dst)->mImageFd;
        pge2d->ge2dinfo.dst_info.vaddr = (char*)mmap( NULL, pge2d->dst_size,
            PROT_READ | PROT_WRITE, MAP_SHARED, ((IONMEM_AllocParams*)pge2d->cmemParm_dst)->mImageFd, 0);
        if (!pge2d->ge2dinfo.dst_info.vaddr) {
            E_GE2D("%s,%d,mmap failed,Not enough memory\n",__func__, __LINE__);
            goto exit;
        }
    }

    D_GE2D("aml_ge2d_mem_alloc: src_info[0].h=%d,dst_info.h=%d\n",
        pge2d->ge2dinfo.src_info[0].canvas_h,pge2d->ge2dinfo.dst_info.canvas_h);
    D_GE2D("aml_ge2d_mem_alloc: src_info[0].format=%d,dst_info.format=%d\n",
        pge2d->ge2dinfo.src_info[0].format,pge2d->ge2dinfo.dst_info.format);
    D_GE2D("src_info[0].size=%d,src_info[1].size=%d,dst_info.size=%d\n",
        pge2d->src_size,pge2d->src2_size,pge2d->dst_size);
    return ge2d_success;
exit:
    aml_ge2d_mem_free_ion(pge2d);
    return ret;
}

void aml_ge2d_mem_free(aml_ge2d_t *pge2d)
{
    ge2d_mem_free(pge2d);
}

int aml_ge2d_mem_alloc(aml_ge2d_t *pge2d)
{
    int ret = -1;
    int dma_fd = -1;
    unsigned int nbytes = 0;

    ge2d_setinfo_size(pge2d);

    if (pge2d->src_size) {
        if (pge2d->ge2dinfo.src_info[0].mem_alloc_type == AML_GE2D_MEM_ION) {
            pge2d->cmemParm_src = malloc(sizeof(IONMEM_AllocParams));
            ret = CMEM_alloc(pge2d->src_size, pge2d->cmemParm_src, false);
            if (ret < 0) {
                E_GE2D("%s,%d,Not enough memory\n",__func__, __LINE__);
                goto exit;
            }
            dma_fd = ((IONMEM_AllocParams*)pge2d->cmemParm_src)->mImageFd;
        } else if (pge2d->ge2dinfo.src_info[0].mem_alloc_type == AML_GE2D_MEM_DMABUF) {
            dma_fd = dmabuf_alloc(GE2D_BUF_INPUT1, pge2d->src_size);
            if (dma_fd < 0) {
                E_GE2D("%s,%d,Not enough memory\n",__func__, __LINE__);
                goto exit;
            }
        }
        pge2d->ge2dinfo.src_info[0].shared_fd = dma_fd;
        pge2d->ge2dinfo.src_info[0].vaddr = (char*)mmap( NULL, pge2d->src_size,
            PROT_READ | PROT_WRITE, MAP_SHARED, dma_fd, 0);

        if (!pge2d->ge2dinfo.src_info[0].vaddr) {
            E_GE2D("%s,%d,mmap failed,Not enough memory\n",__func__, __LINE__);
            goto exit;
        }
    }

    if (pge2d->src2_size) {
        if (pge2d->ge2dinfo.src_info[1].mem_alloc_type == AML_GE2D_MEM_ION) {
            pge2d->cmemParm_src2 = malloc(sizeof(IONMEM_AllocParams));
            ret = CMEM_alloc(pge2d->src2_size, pge2d->cmemParm_src2, false);
            if (ret < 0) {
                E_GE2D("%s,%d,Not enough memory\n",__func__, __LINE__);
                goto exit;
            }
            dma_fd = ((IONMEM_AllocParams*)pge2d->cmemParm_src2)->mImageFd;
        } else if (pge2d->ge2dinfo.src_info[1].mem_alloc_type == AML_GE2D_MEM_DMABUF) {
            dma_fd = dmabuf_alloc(GE2D_BUF_INPUT2, pge2d->src2_size);
            if (dma_fd < 0) {
                E_GE2D("%s,%d,Not enough memory\n",__func__, __LINE__);
                goto exit;
            }
        }
        pge2d->ge2dinfo.src_info[1].shared_fd = dma_fd;
        pge2d->ge2dinfo.src_info[1].vaddr = (char*)mmap( NULL, pge2d->src2_size,
            PROT_READ | PROT_WRITE, MAP_SHARED, dma_fd, 0);
        if (!pge2d->ge2dinfo.src_info[1].vaddr) {
            E_GE2D("%s,%d,mmap failed,Not enough memory\n",__func__, __LINE__);
            goto exit;
        }
    }

    if (pge2d->dst_size) {
        if (pge2d->ge2dinfo.dst_info.mem_alloc_type == AML_GE2D_MEM_ION) {
            pge2d->cmemParm_dst = malloc(sizeof(IONMEM_AllocParams));
            ret = CMEM_alloc(pge2d->dst_size, pge2d->cmemParm_dst, true);
            if (ret < 0) {
                E_GE2D("%s,%d,Not enough memory\n",__func__, __LINE__);
                goto exit;
            }
            dma_fd = ((IONMEM_AllocParams*)pge2d->cmemParm_dst)->mImageFd;
        } else if (pge2d->ge2dinfo.dst_info.mem_alloc_type == AML_GE2D_MEM_DMABUF) {
            dma_fd = dmabuf_alloc(GE2D_BUF_OUTPUT, pge2d->dst_size);
            if (dma_fd < 0) {
                E_GE2D("%s,%d,Not enough memory\n",__func__, __LINE__);
                goto exit;
            }
        }
        pge2d->ge2dinfo.dst_info.shared_fd = dma_fd;
        pge2d->ge2dinfo.dst_info.vaddr = (char*)mmap( NULL, pge2d->dst_size,
            PROT_READ | PROT_WRITE, MAP_SHARED, dma_fd, 0);
        if (!pge2d->ge2dinfo.dst_info.vaddr) {
            E_GE2D("%s,%d,mmap failed,Not enough memory\n",__func__, __LINE__);
            goto exit;
        }
    }

    D_GE2D("aml_ge2d_mem_alloc: src_info[0].h=%d,dst_info.h=%d\n",
        pge2d->ge2dinfo.src_info[0].canvas_h,pge2d->ge2dinfo.dst_info.canvas_h);
    D_GE2D("aml_ge2d_mem_alloc: src_info[0].format=%d,dst_info.format=%d\n",
        pge2d->ge2dinfo.src_info[0].format,pge2d->ge2dinfo.dst_info.format);
    D_GE2D("src_info[0].size=%d,src_info[1].size=%d,dst_info.size=%d\n",
        pge2d->src_size,pge2d->src2_size,pge2d->dst_size);
    return ge2d_success;
exit:
    ge2d_mem_free(pge2d);
    return ret;
}

int aml_ge2d_process(aml_ge2d_info_t *pge2dinfo)
{
    int ret = -1;
    if (fd_ge2d >= 0)
        ret = ge2d_process(fd_ge2d, pge2dinfo);
    return ret;
}

int aml_ge2d_process_ion(aml_ge2d_info_t *pge2dinfo)
{
    int ret = -1;
    if (fd_ge2d >= 0)
        ret = ge2d_process_ion(fd_ge2d, pge2dinfo);
    return ret;
}

int  aml_ge2d_invalid_cache(aml_ge2d_info_t *pge2dinfo)
{
    if (pge2dinfo && pge2dinfo->dst_info.shared_fd != -1) {
        CMEM_invalid_cache(pge2dinfo->dst_info.shared_fd);
    } else {
        E_GE2D("aml_ge2d_invalid err!\n");
        return -1;
    }
    return 0;
}

